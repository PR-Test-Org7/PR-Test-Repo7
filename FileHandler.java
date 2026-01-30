import java.io.*;
import java.nio.file.*;

/**
 * INTENTIONALLY VULNERABLE - FOR TESTING ONLY
 */
public class FileHandler {

    private static final String BASE_DIR = "/var/www/uploads/";

    // VULNERABILITY: Path Traversal (High)
    public byte[] downloadFile(String filename) throws IOException {
        // No validation - allows directory traversal
        File file = new File(BASE_DIR + filename);
        return Files.readAllBytes(file.toPath());
    }

    // VULNERABILITY: Path Traversal variant (High)
    public void deleteFile(String userPath) throws IOException {
        // Direct path manipulation without sanitization
        Path path = Paths.get("/app/data/" + userPath);
        Files.delete(path);
    }

    // VULNERABILITY: Command Injection (Critical)
    public String convertImage(String inputFile, String format) throws IOException {
        // Unsanitized input in shell command
        String command = "convert " + inputFile + " output." + format;
        Process p = Runtime.getRuntime().exec(command);

        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line);
        }
        return output.toString();
    }

    // VULNERABILITY: Command Injection with exec array (Critical)
    public String compressFile(String filename, String options) throws IOException {
        // Options parameter is user-controlled and injected
        String[] cmd = {"/bin/sh", "-c", "tar -czf archive.tar.gz " + options + " " + filename};
        Process process = Runtime.getRuntime().exec(cmd);

        return "Compression started";
    }

    // VULNERABILITY: Path Traversal in write operation (High)
    public void saveUploadedFile(String userFilename, byte[] content) throws IOException {
        // User controls filename - can write to arbitrary locations
        FileOutputStream fos = new FileOutputStream("/var/uploads/" + userFilename);
        fos.write(content);
        fos.close();
    }

    // VULNERABILITY: Command Injection via ProcessBuilder (Critical)
    public String executeScript(String scriptName, String args) throws IOException {
        // User input directly in ProcessBuilder
        ProcessBuilder pb = new ProcessBuilder("bash", "/scripts/" + scriptName, args);
        Process p = pb.start();

        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuilder result = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            result.append(line).append("\n");
        }
        return result.toString();
    }
}
