import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Pattern;

public class SanitizerClaims {
    static int failures = 0;

    /** Each ineffective sanitizer in templates_sanitizers.py must actually be
        defeated. A fixture labelled `ineffective` whose sanitizer in fact works
        puts a vulnerability in the answer key that is not there, and every tool
        correctly reporting nothing would be scored as having missed it. */
    static void claim(String name, boolean defeated) {
        System.out.println((defeated ? "  defeated  " : "  HELD      ") + name);
        if (!defeated) {
            failures++;
        }
    }
    public static void main(String[] a) {
        // wrong-variable: validation passes, raw still dirty
        String raw = "X' OR '1'='1";
        String code = raw.replaceAll("[^A-Z0-9]", "");
        claim("wrong-variable", code.matches("^[A-Z0-9]{1,12}$"));

        // single-pass replace defeated by nesting
        claim("single-pass", "....//x".replace("../", "").contains("../"));

        // decode-after-check: encoded form passes, decodes to traversal
        String enc = "%2e%2e%2fetc%2fpasswd";
        boolean passes = !(enc.contains("..") || enc.contains("/"));
        String dec = URLDecoder.decode(enc, StandardCharsets.UTF_8);
        claim("decode-after-check", passes && dec.contains("../"));

        // discarded return value of replace
        String n = "../etc/passwd";
        n.replace("..", "");
        claim("discarded-return", n.contains(".."));

        // unanchored find() on a crafted authority
        Pattern host = Pattern.compile("api.example.com");
        String url = "https://api.example.com@evil.test/x";
        claim("unanchored-find", host.matcher(url).find()
              && !"api.example.com".equals(URI.create(url).getHost()));

        // canonicalise-after-check
        Path target = Paths.get("/srv/reports/" + "../../etc/passwd");
        claim("toctou-order", target.startsWith("/srv/reports")
              && !target.normalize().startsWith("/srv/reports"));

        // and the SAFE siblings must hold
        String safeCode = "X' OR '1'='1".replaceAll("[^A-Z0-9]", "");
        Path base = Paths.get("/srv/reports");
        boolean safeQuoteFree = !safeCode.contains("'");
        boolean safeStaysUnderBase =
            base.resolve(Paths.get("../../etc/passwd").getFileName()).normalize()
                .startsWith(base);
        if (!safeQuoteFree || !safeStaysUnderBase) {
            System.out.println("  a SAFE sibling does not hold");
            failures++;
        } else {
            System.out.println("  safe siblings hold");
        }

        if (failures > 0) {
            System.out.println(failures + " claim(s) do not hold; the answer key "
                               + "labels a case wrongly");
            System.exit(1);
        }
    }
}
