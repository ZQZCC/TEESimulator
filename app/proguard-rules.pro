-keep class org.matrix.TEESimulator.interception.keystore.** { *; }

-dontwarn javax.naming.**

-keepclasseswithmembers class org.matrix.TEESimulator.App {
    public static void main(java.lang.String[]);
}

-assumenosideeffects class org.matrix.TEESimulator.logging.SystemLogger {
    public void debug(java.lang.String);
    public void verbose(java.lang.String);
}
