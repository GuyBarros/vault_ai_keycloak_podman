package org.demo.ciba;

import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

import java.net.HttpURLConnection;
import java.net.URL;

public class CibaActionReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String id = intent.getStringExtra("id");
        String kind = intent.getStringExtra("kind");
        if (id == null || kind == null) {
            return;
        }
        PendingResult pending = goAsync();
        new Thread(
                        () -> {
                            try {
                                URL url =
                                        new URL(
                                                CibaListenService.BASE_URL
                                                        + "/"
                                                        + kind
                                                        + "/"
                                                        + id);
                                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                                conn.setRequestMethod("POST");
                                conn.setConnectTimeout(5000);
                                conn.setReadTimeout(5000);
                                conn.getResponseCode();
                                conn.disconnect();
                            } catch (Exception ignored) {
                            }
                            NotificationManager nm =
                                    context.getSystemService(NotificationManager.class);
                            nm.cancel(id.hashCode());
                            pending.finish();
                        })
                .start();
    }
}
