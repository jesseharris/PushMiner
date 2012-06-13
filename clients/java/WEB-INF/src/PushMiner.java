import java.io.IOException;
import java.io.PrintWriter;
import java.lang.CloneNotSupportedException;
import java.lang.StringBuilder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PushMiner extends HttpServlet {

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException{
        long nonceStart;
        long nonceEnd;
        String blockHeader;

        try {
            nonceStart = Long.parseLong(request.getParameter("nonce_start"));
            nonceEnd = Long.parseLong(request.getParameter("nonce_end"));
            blockHeader = request.getParameter("block_header");
            response.setContentType("text/plain");
            response.setStatus(200);
            PrintWriter writer = response.getWriter();
            writer.println(this.doWork(blockHeader, nonceStart, nonceEnd).toJSONString());
            writer.close();
        } catch (Exception e) {
            response.setContentType("text/plain");
            response.setStatus(500);
            PrintWriter writer = response.getWriter();
            writer.println("Internal Server Error");
            writer.close();
            return;
        }
    }

    public Result doWork(String blockHeader, long nonceStart, long nonceEnd) throws NoSuchAlgorithmException, CloneNotSupportedException {
        byte[] byteArray = this.hexStringToByteArray(blockHeader);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(byteArray);
        for (long nonce = nonceStart; nonce <= nonceEnd; nonce += 1){
            MessageDigest md1 = (MessageDigest)md.clone();
            md1.update(new byte[] {((byte)(nonce & 0xFF)), ((byte)((nonce & 0xFFFF) >>> 8)), ((byte)((nonce & 0xFFFFFF) >>> 16)), ((byte)((nonce & 0xFFFFFFFF) >>> 24))});
            MessageDigest md2 = MessageDigest.getInstance("SHA-256");
            md2.update(md1.digest());
            byte[] digest = md2.digest();
            if (digest[31] == 0 && digest[30] == 0 && digest[29] == 0 && digest[28] == 0) {
                return new Result(true, nonce, nonceStart, nonceEnd);
            }
        }
        return new Result(false, -1, nonceStart, nonceEnd);
    }

    public byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] byteArray = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            byteArray[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }
        return byteArray;
    }

    private class Result {
        public Boolean shareFound;
        public long nonce;
        public long nonceStart;
        public long nonceStop;

        public Result(Boolean shareFound, long nonce, long nonceStart, long nonceStop) {
            this.shareFound = shareFound;
            this.nonce = nonce;
            this.nonceStart = nonceStart;
            this.nonceStop = nonceStop;
        }

        public String getShareFoundAsLowerCaseString() {
            return this.shareFound == true ? "true" : "false";
        }

        public String toJSONString() {
            return String.format("{ \"share_found\" : %s, \"nonce\" : %d, \"nonce_start\" : %d, \"nonce_end\" : %d }", this.getShareFoundAsLowerCaseString(), this.nonce, this.nonceStart, this.nonceStop);
        }
    }
}
