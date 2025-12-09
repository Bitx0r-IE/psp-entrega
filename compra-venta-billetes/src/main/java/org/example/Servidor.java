package org.example;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class Servidor {

    private final int port;
    private final KeyPair serverKeyPair;
    private final Map<String, AuxiliaryClasses.User> users = new ConcurrentHashMap<>();
    private final Map<String, AuxiliaryClasses.Ticket> tickets = new ConcurrentHashMap<>();

    public Servidor(int port) throws Exception {
        this.port = port;
        this.serverKeyPair = AuxiliaryClasses.CryptoUtils.generateRSAKeyPair();
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

            AuxiliaryClasses.Message pkmsg = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.PUBLIC_KEY);
            pkmsg.fields.put("serverPub", Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded()));
            out.writeObject(pkmsg);

            while (true) {
                AuxiliaryClasses.Message msg = (AuxiliaryClasses.Message) in.readObject();
                switch (msg.type) {
                    case REGISTER -> handleRegisterLoop(msg, out, in);
                    case LIST_TICKETS -> handleList(out);
                    case BUY -> handleBuy(msg, out);
                    default -> {
                        AuxiliaryClasses.Message e = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.ERROR);
                        e.fields.put("msg", "Comando desconocido");
                        out.writeObject(e);
                    }
                }
            }

        } catch (Exception e) {
            System.out.println("Cliente desconectado");
        }
    }

    private void handleRegisterLoop(AuxiliaryClasses.Message msg, ObjectOutputStream out, ObjectInputStream in) throws Exception {
        boolean registrado = false;
        while (!registrado) {
            AuxiliaryClasses.Message resp = validarCamposRegistro(msg);
            if (resp != null) {
                out.writeObject(resp);
                // Esperar nuevo mensaje de registro
                msg = (AuxiliaryClasses.Message) in.readObject();
                continue;
            }

            if (!AuxiliaryClasses.Validator.validatePassword(msg.fields.get("passwordRaw"))) {
                resp = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.REGISTER_RESPONSE);
                resp.fields.put("status", "ERROR");
                resp.fields.put("msg", "Contraseña insegura: min 8 chars, mayúscula, minúscula y número");
                out.writeObject(resp);
                msg = (AuxiliaryClasses.Message) in.readObject();
                continue;
            }

            String usuario = msg.fields.get("usuario");
            if (users.containsKey(usuario)) {
                resp = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.REGISTER_RESPONSE);
                resp.fields.put("status", "ERROR");
                resp.fields.put("msg", "Usuario ya existe");
                out.writeObject(resp);
                msg = (AuxiliaryClasses.Message) in.readObject();
                continue;
            }

            byte[] pwdEnc = Base64.getDecoder().decode(msg.fields.get("passwordEncrypted"));
            byte[] pwdBytes = AuxiliaryClasses.CryptoUtils.rsaDecrypt(pwdEnc, serverKeyPair.getPrivate());
            String password = new String(pwdBytes);

            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            byte[] hash = AuxiliaryClasses.CryptoUtils.pbkdf2(password.toCharArray(), salt);

            byte[] pkBytes = Base64.getDecoder().decode(msg.fields.get("clientPub"));
            PublicKey clientPub = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pkBytes));

            AuxiliaryClasses.User u = new AuxiliaryClasses.User(msg.fields.get("nombre"), msg.fields.get("apellido"), Integer.parseInt(msg.fields.get("edad")), msg.fields.get("email"), usuario, hash, salt, clientPub);
            users.put(usuario, u);

            resp = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.REGISTER_RESPONSE);
            resp.fields.put("status", "OK");
            resp.fields.put("msg", "Registro completado con éxito");
            out.writeObject(resp);
            registrado = true;
        }
    }

    private AuxiliaryClasses.Message validarCamposRegistro(AuxiliaryClasses.Message msg) {
        AuxiliaryClasses.Message err = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.REGISTER_RESPONSE);
        if (!AuxiliaryClasses.Validator.validateNombre(msg.fields.get("nombre"))) {
            err.fields.put("status", "ERROR");
            err.fields.put("msg", "Nombre inválido");
            return err;
        }
        if (!AuxiliaryClasses.Validator.validateApellido(msg.fields.get("apellido"))) {
            err.fields.put("status", "ERROR");
            err.fields.put("msg", "Apellido inválido");
            return err;
        }
        if (!AuxiliaryClasses.Validator.validateEdad(msg.fields.get("edad"))) {
            err.fields.put("status", "ERROR");
            err.fields.put("msg", "Edad no válida (18-120)");
            return err;
        }
        if (!AuxiliaryClasses.Validator.validateEmail(msg.fields.get("email"))) {
            err.fields.put("status", "ERROR");
            err.fields.put("msg", "Email inválido");
            return err;
        }
        if (!AuxiliaryClasses.Validator.validateUsuario(msg.fields.get("usuario"))) {
            err.fields.put("status", "ERROR");
            err.fields.put("msg", "Usuario inválido (4-20 alfanuméricos)");
            return err;
        }
        return null;
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

        String payload = usuario + "|" + ticketId + "|" + nonce;
        boolean verified = AuxiliaryClasses.CryptoUtils.verify(payload.getBytes(), signature, u.publicKey);
        if (!verified) {
            resp.fields.put("state", "RECHAZADA");
            resp.fields.put("msg", "Firma inválida");
            out.writeObject(resp);
            return;
        }

        AuxiliaryClasses.Ticket t = tickets.get(ticketId);
        if (t == null) {
            resp.fields.put("state", "RECHAZADA");
            resp.fields.put("msg", "Billete no encontrado");
            out.writeObject(resp);
            return;
        }

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

    public static void main(String[] args) {
        int puerto = 5000;
        try {
            Servidor servidor = new Servidor(puerto);
            System.out.println("Servidor iniciado en puerto " + puerto);
            servidor.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
