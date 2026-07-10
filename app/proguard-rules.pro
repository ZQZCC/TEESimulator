-keep class org.matrix.TEESimulator.interception.keystore.** { *; }

-dontwarn javax.naming.**

-keepclasseswithmembers class org.matrix.TEESimulator.App {
    public static void main(java.lang.String[]);
}

-assumenosideeffects class org.matrix.TEESimulator.logging.SystemLogger {
    public void debug(java.lang.String);
    public void info(java.lang.String);
    public void warning(java.lang.String, java.lang.Throwable);
    public void error(java.lang.String, java.lang.Throwable);
    public void verbose(java.lang.String);
}
