package org.demo.ciba;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView view = new TextView(this);
        view.setPadding(48, 96, 48, 48);
        view.setTextSize(18);
        view.setText(
                "CIBA device is listening.\n\n"
                        + "Leave this app running. When the agent asks to list users, "
                        + "Approve / Deny appear as a native notification.\n\n"
                        + "Vault will not mint database credentials until you approve.");
        setContentView(view);

        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)
                        != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(
                    new String[] {android.Manifest.permission.POST_NOTIFICATIONS}, 1);
        }
        startForegroundService(new Intent(this, CibaListenService.class));
    }
}
