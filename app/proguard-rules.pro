-repackageclasses ''
-allowaccessmodification

-keep class io.nekohasekai.sagernet.** { *;}
-keep class com.github.exclavenetwork.exclave.core.app.observatory.** { *; }

# SnakeYaml
-keep class org.yaml.snakeyaml.** { *; }

# JNA
-keep class com.sun.jna.** { *; }
-keep class java.lang.reflect.** { *; }
-keepclassmembers class * extends com.sun.jna.** { *; }
-keepclassmembers class * {
    @com.sun.jna.Function$Invoke *;
    @com.sun.jna.Callback *;
}
-dontwarn java.awt.**
-dontwarn com.sun.jna.**

-dontobfuscate
-keepattributes SourceFile
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes Exceptions
-keepattributes InnerClasses
-keepattributes EnclosingMethod

-dontwarn java.beans.BeanInfo
-dontwarn java.beans.FeatureDescriptor
-dontwarn java.beans.IntrospectionException
-dontwarn java.beans.Introspector
-dontwarn java.beans.PropertyDescriptor
-dontwarn java.beans.Transient
-dontwarn java.beans.VetoableChangeListener
-dontwarn java.beans.VetoableChangeSupport