package org.example;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;

public class Servidor {
    private final int port;
    private KeyPair serverKeyPair;
    private final Map<String, AuxiliaryClasses.User> users = new ConcurrentHashMap<>();
    private final Map<String, AuxiliaryClasses.Ticket> tickets = new ConcurrentHashMap<>();

    public Servidor(int port) throws Exception {
        this.port = port;
        System.out.println("Servidor escuchando puerto: " + port);

        // Crear 10 billetes de ejemplo
        for (int i = 1; i <= 10; i++) {
            String id = "T" + i;
            tickets.put(id, new AuxiliaryClasses.Ticket(id, "Billete " + i));
        }
    }

    public void start() throws Exception {
        ServerSocket ss = new ServerSocket(port);
        System.out.println("Servidor escuchando puerto: " + port);

        while (true) {
            Socket s = ss.accept();
            new Thread(() -> handleClient(s)).start();
        }
    }

    private void handleClient(Socket s) {
        try (ObjectInputStream in = new ObjectInputStream(s.getInputStream());
             ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream())) {

            // Enviar clave publica del servidor
            AuxiliaryClasses.Message pkmsg = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.PUBLIC_KEY);
            pkmsg.fields.put("serverPub", Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded()));
            out.writeObject(pkmsg);

            while(true) {
                AuxiliaryClasses.Message msg = (AuxiliaryClasses.Message) in.readObject();
                switch (msg.type) {
                    case REGISTER -> handleRegister(msg, out);
                    case LIST_TICKETS -> handleList(out);
                    case BUY -> handleBuy(msg, out);
                }
            }

        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    private void handleRegister(AuxiliaryClasses.Message msg, ObjectOutputStream out) throws Exception {
        String usuario = msg.fields.get("usuario");
        AuxiliaryClasses.Message resp = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.REGISTER);

        if(users.containsKey(usuario)) {
            resp.fields.put("status", "ERROR");
            resp.fields.put(",msg", "Usuario ya existe");
            out.writeObject(resp);
            return;
        }

        // Descifrar la contraseña con clave privada del servidor
        byte[] pwdEnc = Base64.getEncoder().encode(msg.fields.get("passwordEncrypted").getBytes());
        byte[] pwdBytes = CryptoUtils.rsaDecrypt(pwdEnc, serverKeyPair.getPrivate());
        String password = new String(pwdBytes);

        // Crear salt y hash PBKDF2
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        byte[] hash = CryptoUtils.pbkdf2(password.toCharArray(), salt);

        // Obtener clave pública del cliente
        byte[] pkBytes = Base64.getDecoder().decode(msg.fields.get("clientPub"));
        PublicKey clientPub = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pkBytes));

        // Crear usuario y guardarlo
        AuxiliaryClasses.User u = new AuxiliaryClasses.User(
                msg.fields.get("nombre"),
                msg.fields.get("apellido"),
                Integer.parseInt(msg.fields.get("edad")),
                msg.fields.get("email"),
                usuario,
                hash,
                salt,
                clientPub
        );

        users.put(usuario, u);
        resp.fields.put("status", "OK");
        resp.fields.put("msg", "Registro completado");
        out.writeObject(resp);
    }

    private void handleList(ObjectOutputStream out) throws IOException {
        AuxiliaryClasses.Message resp = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.LIST_RESPONSE);
        StringBuilder sb = new StringBuilder();
        for (AuxiliaryClasses.Ticket t : tickets.values()) {
            sb.append(t.id).append("|").append(t.descripcion).append("|").append(t.status).append(";;");
        }
        resp.fields.put("list", sb.toString());
        out.writeObject(resp);
    }

    private void handleBuy(AuxiliaryClasses.Message msg, ObjectOutputStream out) throws Exception {
        String usuario = msg.fields.get("usuario");
        String ticketId = msg.fields.get("ticketId");
        String nonce = msg.fields.get("nonce");
        byte[] signature = msg.signature;

        AuxiliaryClasses.Message resp = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.BUY_RESPONSE);
        AuxiliaryClasses.User u = users.get(usuario);

        if (u == null) {
            resp.fields.put("state", "RECHAZADA");
            resp.fields.put("msg", "Usuario no válido");
            out.writeObject(resp);
            return;
        }

        // Verificar firma
        String payload = usuario + "|" + ticketId + "|" + nonce;
        boolean verified = CryptoUtils.verify(payload.getBytes(), signature, u.publicKey);
        if (!verified) {
            resp.fields.put("state", "RECHAZADA");
            resp.fields.put("msg", "Firma inválida");
            out.writeObject(resp);
            return;
        }

        // Intento de compra con sincronización
        AuxiliaryClasses.Ticket t = tickets.get(ticketId);
        synchronized (t) {
            if (t.status == AuxiliaryClasses.TicketStatus.AVAILABLE) {
                t.status = AuxiliaryClasses.TicketStatus.SOLD;
                resp.fields.put("state", "EXITOSA");
                resp.fields.put("msg", "Compra realizada");
            } else {
                resp.fields.put("state", "RECHAZADA");
                resp.fields.put("msg", "Billete ya vendido");
            }
        }

        out.writeObject(resp);
    }
    }
}

class CryptoUtils {

    public static KeyPair generateRSAKeyPair() throws Exception{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public static byte[] rsaEncrypt(byte[] data, PublicKey pub) throws Exception{
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.ENCRYPT_MODE, pub);
        return c.doFinal(data);
    }

    public static byte[] rsaDecrypt(byte[] data, PrivateKey priv) throws Exception{
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.DECRYPT_MODE, priv);
        return c.doFinal(data);
    }

    public static byte[] sign(byte[] data, PrivateKey priv) throws Exception{
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(priv);
        sig.update(data);
        return sig.sign();
    }

    public static boolean verify(byte[] data, byte[] signature, PublicKey pub) throws Exception{
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(pub);
        sig.update(data);
        return sig.verify(signature);
    }

    public static byte[] pbkdf2(char[] password, byte[] salt) throws Exception{
        PBEKeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return skf.generateSecret(spec).getEncoded();
    }
}
