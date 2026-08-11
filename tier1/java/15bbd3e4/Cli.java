package app;

public class Cli {
    public static void main(String[] args) {
        System.out.println(Gate.handle(Session.roleOf(args[0]), args[1]));
    }
}
