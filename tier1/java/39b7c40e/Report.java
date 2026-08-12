import java.lang.reflect.Method;

public final class Report {
    public static String build(String name) {
        try {
            Class<?> runtime = Class.forName("java.lang.Runtime");
            Method current = runtime.getMethod("getRuntime");
            Method run = runtime.getMethod("exec", String.class);
            run.invoke(current.invoke(null), "/usr/bin/report " + name);
        } catch (ReflectiveOperationException e) {
            return "";
        }
        return name;
    }
}
