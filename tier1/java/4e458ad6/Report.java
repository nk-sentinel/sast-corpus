import java.lang.reflect.Method;

public final class Report {
    public static String build(String name) {
        try {
            Class<?> strings = Class.forName("java.lang.String");
            Method upper = strings.getMethod("toUpperCase");
            return (String) upper.invoke(name);
        } catch (ReflectiveOperationException e) {
            return "";
        }
    }
}
