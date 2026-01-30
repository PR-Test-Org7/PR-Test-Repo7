import java.sql.*;
import java.util.*;

/**
 * INTENTIONALLY VULNERABLE - FOR TESTING ONLY
 */
public class DatabaseService {

    // VULNERABILITY: Hardcoded Credentials (Critical)
    private static final String DATABASE_URL = "jdbc:postgresql://prod-db.example.com:5432/maindb";
    private static final String DB_USER = "postgres";
    private static final String DB_PASS = "P@ssw0rd123!";
    private static final String AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    // VULNERABILITY: SQL Injection (Critical)
    public List<String> searchProducts(String category, String keyword) throws SQLException {
        Connection conn = DriverManager.getConnection(DATABASE_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();

        // Vulnerable SQL concatenation
        String sql = "SELECT product_name, price FROM products WHERE category = '" + category +
                     "' AND name LIKE '%" + keyword + "%' ORDER BY price";

        ResultSet rs = stmt.executeQuery(sql);
        List<String> results = new ArrayList<>();

        while (rs.next()) {
            results.add(rs.getString("product_name"));
        }
        return results;
    }

    // VULNERABILITY: SQL Injection in UPDATE (Critical)
    public void updateUserEmail(String userId, String newEmail) throws SQLException {
        Connection conn = DriverManager.getConnection(DATABASE_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();

        // Another SQL injection point
        String update = "UPDATE users SET email = '" + newEmail +
                       "', updated_at = NOW() WHERE user_id = " + userId;
        stmt.executeUpdate(update);
    }

    // VULNERABILITY: SQL Injection in DELETE (Critical)
    public void deleteOldRecords(String tableName, String condition) throws SQLException {
        Connection conn = DriverManager.getConnection(DATABASE_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();

        // Dynamic table name and condition - SQL injection
        String delete = "DELETE FROM " + tableName + " WHERE " + condition;
        stmt.executeUpdate(delete);
    }

    // VULNERABILITY: Insecure Deserialization (Critical)
    public Object loadSessionData(byte[] sessionData) throws Exception {
        java.io.ObjectInputStream ois = new java.io.ObjectInputStream(
            new java.io.ByteArrayInputStream(sessionData)
        );
        // Deserializing untrusted data without validation
        return ois.readObject();
    }
}
