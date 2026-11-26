#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

import pathlib
import unittest
import xml.etree.ElementTree as ET


MAIN = pathlib.Path(__file__).resolve().parents[1] / "app/src/main"
ANDROID = "{http://schemas.android.com/apk/res/android}"


class ImportSecurity(unittest.TestCase):
    def test_platform_cannot_dispatch_secret_link_by_scheme(self):
        manifest = ET.parse(MAIN / "AndroidManifest.xml")
        for activity in manifest.findall(".//activity") + manifest.findall(".//activity-alias"):
            for data in activity.findall("intent-filter/data"):
                self.assertNotEqual(data.get(ANDROID + "scheme"), "pipe")

    def test_pending_import_is_absent_from_saved_activity_state(self):
        activity = (MAIN / "java/io/pipe/app/MainActivity.kt").read_text()
        save = activity.split("override fun onSaveInstanceState", 1)[1].split("\n    }", 1)[0]
        self.assertNotIn("pendingLink", save)
        self.assertNotIn('savedInstanceState.getString("link")', activity)

    def test_settings_routes_secret_copies_through_the_clipboard_policy(self):
        settings = (MAIN / "java/io/pipe/app/SettingsView.kt").read_text()
        self.assertFalse(".setPrimaryClip(" in settings)
        self.assertIn("SecretClipboard.supported", settings)


if __name__ == "__main__":
    unittest.main()
