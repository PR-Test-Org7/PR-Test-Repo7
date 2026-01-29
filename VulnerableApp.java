import java.io.*;
import java.sql.*;
import java.util.*;
import javax.servlet.http.*;

/**
 * INTENTIONALLY VULNERABLE APPLICATION - FOR EDUCATIONAL PURPOSES ONLY
 * DO NOT USE IN PRODUCTION
 */
public class VulnerableApp {

    // VULNERABILITY 1: Hardcoded Credentials (Critical)
    private static final String DB_PASSWORD = "admin123";
    private static final String API_KEY = "sk_live_51234567890abcdef";

    // VULNERABILITY 2: SQL Injection (Critical)
    public User loginUser(String username, String password) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app", "root", DB_PASSWORD);
        Statement stmt = conn.createStatement();

        // Direct string concatenation - SQL Injection vulnerability
        String query = "SELECT * FROM users WHERE username = '" + username +
                      "' AND password = '" + password + "'";
        ResultSet rs = stmt.executeQuery(query);

        if (rs.next()) {
            return new User(rs.getString("username"), rs.getString("email"));
        }
        return null;
    }

    // VULNERABILITY 3: Command Injection (Critical)
    public String executePing(String host) throws IOException {
        // Direct use of user input in system command
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec("ping -c 4 " + host);

        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    // VULNERABILITY 4: Path Traversal (High)
    public String readFile(String filename) throws IOException {
        // No validation - allows reading any file on system
        File file = new File("/var/app/files/" + filename);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\n");
        }
        reader.close();
        return content.toString();
    }

    // VULNERABILITY 5: Insecure Deserialization (Critical)
    public Object deserializeObject(String base64Data) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(base64Data);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        // Deserializing untrusted data
        return ois.readObject();
    }

    // VULNERABILITY 6: Cross-Site Scripting (XSS) (High)
    public void displayUserComment(HttpServletResponse response, String comment) throws IOException {
        PrintWriter out = response.getWriter();
        // No sanitization of user input before rendering
        out.println("<html><body>");
        out.println("<div>User comment: " + comment + "</div>");
        out.println("</body></html>");
    }

    // Helper class
    static class User {
        String username;
        String email;

        public User(String username, String email) {
            this.username = username;
            this.email = email;
        }
    }
}
