package org.example;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Gestionar clientes concurrentes, validar registros, manetener el catálogo de billetes y procesar compras seguras
 * mediante firma digital
 */
public class Servidor {

    private final int port;
    private final KeyPair serverKeyPair; // Par de claves RSA del servidor
    private final Map<String, AuxiliaryClasses.User> users = new ConcurrentHashMap<>(); // Usuarios registrados
    private final Map<String, AuxiliaryClasses.Ticket> tickets = new ConcurrentHashMap<>(); // Catalogo de billetes

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

    /**
     * Constructor:
     * - Genera clave RSA del servidor (para descifrar constraseñas)
     * - Crea una lista inicial de billetes
     * - Prepara estructuraas de datos concurrentes
     *
     * @param port
     * @throws Exception
     */
    public Servidor(int port) throws Exception {
        this.port = port;
        // Clave RSA del servidor
        this.serverKeyPair = AuxiliaryClasses.CryptoUtils.generateRSAKeyPair();

        // Crear billetes iniciales
        for (int i = 1; i <= 10; i++) {
            String id = "T" + i;
            tickets.put(id, new AuxiliaryClasses.Ticket(id, "Billete número " + i));
        }
    }

    /**
     * Escucha conexiones y lanza un hilo por cliente
     *
     * @throws Exception
     */
    public void start() throws Exception {
        ServerSocket ss = new ServerSocket(port);
        System.out.println("Servidor escuchando puerto: " + port);

        while (true) {
            Socket s = ss.accept(); // Espera cliente
            new Thread(() -> handleClient(s)).start(); // Hilo nuevo por cliente nuevo
        }
    }

    /**
     * Metodo que atiende a cada cliente de forma independiente en su proipio hilo y redirecciona dependiendo de la opción escogida por el mismo
     *
     * @param s
     */
    private void handleClient(Socket s) {
        try (ObjectInputStream in = new ObjectInputStream(s.getInputStream());
             ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream())) {

            // Enviar clave pública del servidor para que el cliente pueda cifrar la contraseña
            AuxiliaryClasses.Message pkmsg = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.PUBLIC_KEY);
            pkmsg.fields.put("serverPub", Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded()));
            out.writeObject(pkmsg);

            boolean registrado = false;
            String usuarioActual = null;

            // Bucle principal de escucha de comandos de cliente
            while (true) {
                AuxiliaryClasses.Message msg = (AuxiliaryClasses.Message) in.readObject();
                switch (msg.type) {
                    case REGISTER -> {
                        handleRegisterLoop(msg, out, in);
                        usuarioActual = msg.fields.get("usuario");
                        registrado = true;
                    }
                    case LIST_TICKETS -> {
                        handleList(out); // Se podría obligar a estar registrado para ver el listado de billetes pero no lo veo necesario ni logico en esta situación
                        /*
                        if (registrado && users.containsKey((usuarioActual))) {
                            handleList(out);
                        } else {
                            AuxiliaryClasses.Message err = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.ERROR);
                            err.fields.put("msg", "Debe registrarse primero para listar billetes");
                            out.writeObject(err);
                        }
                        */
                    }
                    case BUY -> {
                        if (registrado && users.containsKey(usuarioActual)) {
                            handleBuy(msg, out);
                        } else {
                            AuxiliaryClasses.Message err = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.BUY_RESPONSE);
                            err.fields.put("transactionId", UUID.randomUUID().toString());
                            err.fields.put("state", "RECHAZADA");
                            err.fields.put("msg", "Debe registrarse primero para comprar billetes");
                            out.writeObject(err);
                        }
                    }
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

    /**
     * Metodo que gestiona el registro del cliente usando validación de datos validos del cliente y realiza un descrifrado RSA de la contraseña,
     * PBKDF3 + salt para almacenar el hash seguro de la clave publica del cliente
     *
     * @param msg
     * @param out
     * @param in
     * @throws Exception
     */
    private void handleRegisterLoop(AuxiliaryClasses.Message msg, ObjectOutputStream out, ObjectInputStream in) throws Exception {
        boolean registrado = false;

        while (!registrado) {
            // VAlidación de campos del registro
            AuxiliaryClasses.Message resp = validarCamposRegistro(msg);
            if (resp != null) {
                out.writeObject(resp);
                msg = (AuxiliaryClasses.Message) in.readObject();
                continue;
            }

            // Validación contraseñas
            if (!AuxiliaryClasses.Validator.validatePassword(msg.fields.get("passwordRaw"))) {
                resp = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.REGISTER_RESPONSE);
                resp.fields.put("status", "ERROR");
                resp.fields.put("msg", "Contraseña insegura: min 8 chars, mayúscula, minúscula y número");
                out.writeObject(resp);
                msg = (AuxiliaryClasses.Message) in.readObject();
                continue;
            }

            // Valida si el usuario ya existe
            String usuario = msg.fields.get("usuario");
            if (users.containsKey(usuario)) {
                resp = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.REGISTER_RESPONSE);
                resp.fields.put("status", "ERROR");
                resp.fields.put("msg", "Usuario ya existe");
                out.writeObject(resp);
                msg = (AuxiliaryClasses.Message) in.readObject();
                continue;
            }

            // Descifrar contraseña usando RSA privada del servidor
            byte[] pwdEnc = Base64.getDecoder().decode(msg.fields.get("passwordEncrypted"));
            byte[] pwdBytes = AuxiliaryClasses.CryptoUtils.rsaDecrypt(pwdEnc, serverKeyPair.getPrivate());
            String password = new String(pwdBytes);

            // PBKDF2: Hash seguro + SALT
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            byte[] hash = AuxiliaryClasses.CryptoUtils.pbkdf2(password.toCharArray(), salt);

            // Convertir clave publica ddel cliente
            byte[] pkBytes = Base64.getDecoder().decode(msg.fields.get("clientPub"));
            PublicKey clientPub = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pkBytes));

            // Crear usuario seguro
            AuxiliaryClasses.User u = new AuxiliaryClasses.User(msg.fields.get("nombre"), msg.fields.get("apellido"), Integer.parseInt(msg.fields.get("edad")), msg.fields.get("email"), usuario, hash, salt, clientPub);
            users.put(usuario, u);

            // Respuesta OK
            resp = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.REGISTER_RESPONSE);
            resp.fields.put("status", "OK");
            resp.fields.put("msg", "Registro completado con éxito");
            out.writeObject(resp);
            registrado = true;
        }
    }

    /**
     * Utilizo la clase Validator del fichero AuxiliaryClasses que contiene los regex y validaciones a implementar
     * para comprobar los campos de registro. Retornará null o un Message 'err' indicando que validación no ha sido correcta
     *
     * @param msg
     * @return
     */
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

    /**
     * Metodo encargado de enviar al cliente la lista actualizada de billetes
     *
     * @param out
     * @throws IOException
     */
    private void handleList(ObjectOutputStream out) throws IOException {
        AuxiliaryClasses.Message resp = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.LIST_RESPONSE);
        StringBuilder sb = new StringBuilder();
        for (AuxiliaryClasses.Ticket t : tickets.values()) {
            sb.append(t.id).append("|").append(t.descripcion).append("|").append(t.status).append(";; \n");
        }
        resp.fields.put("list", sb.toString());
        out.writeObject(resp);
    }

    /**
     * Metodo encargado de procesar la comrpa de un billete:
     * - Verifica usuario
     * - Verifica firma digital RSA del cliente
     * - Asegura exclusión mutua con synchronized(t)
     * - Marca el billete como vendido si está disponible
     * - Devuelve estado EXITOSA o RECHAZADA
     *
     * @param msg
     * @param out
     * @throws Exception
     */
    private void handleBuy(AuxiliaryClasses.Message msg, ObjectOutputStream out) throws Exception {
        String usuario = msg.fields.get("usuario");
        String ticketId = msg.fields.get("ticketId");
        String nonce = msg.fields.get("nonce");
        byte[] signature = msg.signature;

        AuxiliaryClasses.Message resp = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.BUY_RESPONSE);
        AuxiliaryClasses.User u = users.get(usuario);

        String transactionId = UUID.randomUUID().toString();

        // VAlidación de usuario
        if (u == null) {
            resp.fields.put("transactionId", transactionId);
            resp.fields.put("state", "RECHAZADA");
            resp.fields.put("msg", "Usuario no válido");
            out.writeObject(resp);
            return;
        }

        // Validación de firma digital
        String payload = usuario + "|" + ticketId + "|" + nonce;
        boolean verified = AuxiliaryClasses.CryptoUtils.verify(payload.getBytes(), signature, u.publicKey);
        if (!verified) {
            resp.fields.put("transactionId", transactionId);
            resp.fields.put("state", "RECHAZADA");
            resp.fields.put("msg", "Firma inválida");
            out.writeObject(resp);
            return;
        }

        // Validación cliente
        AuxiliaryClasses.Ticket t = tickets.get(ticketId);
        if (t == null) {
            resp.fields.put("transactionId", transactionId);
            resp.fields.put("state", "RECHAZADA");
            resp.fields.put("msg", "Billete no encontrado");
            out.writeObject(resp);
            return;
        }

        // Exclusión mutua; evitarr doble compra simultanea
        synchronized (t) {
            if (t.status == AuxiliaryClasses.TicketStatus.AVAILABLE) {
                t.status = AuxiliaryClasses.TicketStatus.SOLD;
                resp.fields.put("transactionId", transactionId);
                resp.fields.put("state", "EXITOSA");
                resp.fields.put("msg", "Compra realizada");
            } else {
                resp.fields.put("transactionId", transactionId);
                resp.fields.put("state", "RECHAZADA");
                resp.fields.put("msg", "Billete ya vendido");
            }
        }

        // Log de la transacción
        System.out.println("Transacción " + transactionId + ": Usuario=" + usuario + ", Ticket=" + ticketId + ", Estado=" + resp.fields.get("state"));

        out.writeObject(resp);
    }
}
