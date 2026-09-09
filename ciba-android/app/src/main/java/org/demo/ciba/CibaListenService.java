package org.demo.ciba;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Handler;
import android.os.Looper;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

public class CibaListenService extends Service {
    static final String CHANNEL_LISTEN = "ciba-listen";
    static final String CHANNEL_APPROVE = "ciba-approve";
    static final String BASE_URL = "http://10.0.2.2:8093";

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Set<String> shown = new HashSet<>();
    private boolean running = true;

    private final Runnable poll = new Runnable() {
        @Override
        public void run() {
            if (!running) {
                return;
            }
            new Thread(CibaListenService.this::pollOnce).start();
            handler.postDelayed(this, 1500);
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.createNotificationChannel(
                new NotificationChannel(
                        CHANNEL_LISTEN, "CIBA listener", NotificationManager.IMPORTANCE_LOW));
        NotificationChannel approve =
                new NotificationChannel(
                        CHANNEL_APPROVE,
                        "CIBA approval",
                        NotificationManager.IMPORTANCE_HIGH);
        approve.enableVibration(true);
        approve.setBypassDnd(true);
        nm.createNotificationChannel(approve);
        startForeground(
                1,
                new Notification.Builder(this, CHANNEL_LISTEN)
                        .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
                        .setContentTitle("CIBA device")
                        .setContentText("Waiting for a Vault step-up request")
                        .setOngoing(true)
                        .build());
        handler.post(poll);
    }

    private void pollOnce() {
        try {
            URL url = new URL(BASE_URL + "/pending");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            BufferedReader reader =
                    new BufferedReader(
                            new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
            StringBuilder body = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                body.append(line);
            }
            reader.close();
            JSONArray items = new JSONArray(body.toString());
            Set<String> live = new HashSet<>();
            for (int i = 0; i < items.length(); i++) {
                JSONObject item = items.getJSONObject(i);
                String id = item.optString("id");
                if (id.isEmpty()) {
                    continue;
                }
                live.add(id);
                if (shown.add(id)) {
                    showApproval(item);
                }
            }
            NotificationManager nm = getSystemService(NotificationManager.class);
            Set<String> stale = new HashSet<>(shown);
            stale.removeAll(live);
            for (String id : stale) {
                shown.remove(id);
                nm.cancel(id.hashCode());
            }
        } catch (Exception ignored) {
            // Emulator may race the host; keep polling.
        }
    }

    private void showApproval(JSONObject item) {
        String id = item.optString("id");
        String user = item.optString("login_hint", "user");
        String binding = item.optString("binding_message", "list-users");
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.notify(
                id.hashCode(),
                new Notification.Builder(this, CHANNEL_APPROVE)
                        .setSmallIcon(android.R.drawable.ic_dialog_alert)
                        .setContentTitle("Vault needs your approval")
                        .setContentText(user + " · " + binding)
                        .setStyle(
                                new Notification.BigTextStyle()
                                        .bigText(
                                                user
                                                        + " asked the agent to "
                                                        + binding
                                                        + ".\nVault will not issue DB credentials until you approve."))
                        .setCategory(Notification.CATEGORY_STATUS)
                        .setAutoCancel(true)
                        .addAction(android.R.drawable.ic_input_add, "Approve", action("approve", id))
                        .addAction(android.R.drawable.ic_delete, "Deny", action("deny", id))
                        .build());
    }

    private PendingIntent action(String kind, String id) {
        Intent intent = new Intent(this, CibaActionReceiver.class);
        intent.setAction("org.demo.ciba." + kind);
        intent.putExtra("kind", kind);
        intent.putExtra("id", id);
        int requestCode = (kind + id).hashCode();
        return PendingIntent.getBroadcast(
                this,
                requestCode,
                intent,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        running = false;
        handler.removeCallbacks(poll);
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
