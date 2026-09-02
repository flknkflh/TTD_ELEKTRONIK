# gomobile-generated JNI classes must survive shrinking.
-keep class go.** { *; }
-keep class id.example.pqcsign.mobilebridge.** { *; }
-dontwarn go.**
