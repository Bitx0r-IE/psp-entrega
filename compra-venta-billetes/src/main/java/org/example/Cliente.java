package org.example;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

/**
 * Gestiona la comunicación con el servidor, permite registrar usuarios,
 * listar billetes y realizar compras con firma digital.
 *
 * Funcionalidades principales:
 * - Autenticación segura mediante RSA
 * - Envío de datos cifrados al servidor
 * - Firma digital en la compra de billetes
 * - Manejo de estados y respuestas del servidor
 */
public class Cliente {

    private Socket socket;  // Conexión TCP con el servidor
    private ObjectOutputStream out;
    private ObjectInputStream in;
    private PublicKey serverPub;    // Clave pública del servidor
    private KeyPair clientKeyPair; // Clave del usuario para firmar compras

    // Establece la conexión y recibe la clave pública del servidor
    public Cliente(String host, int port) throws Exception {
        socket = new Socket(host, port);
        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());

        // Recibir clave pública del servidor
        AuxiliaryClasses.Message msg = (AuxiliaryClasses.Message) in.readObject();
        if (msg.type == AuxiliaryClasses.Message.Type.PUBLIC_KEY) {

            // Convertir la clave pública enviada en Base64 a objeto PublicKey
            byte[] keyBytes = Base64.getDecoder().decode(msg.fields.get("serverPub"));
            serverPub = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
        }
    }

    public static void main(String[] args) {
        try {
            Cliente c = new Cliente("localhost", 5000);
            c.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Menú interactivo del cliente
    public void start() throws Exception {
        Scanner sc = new Scanner(System.in);
        boolean running = true;

        while (running) {
            System.out.println("\n=== Menú Cliente ===");
            System.out.println("1. Registrar usuario");
            System.out.println("2. Listar billetes disponibles");
            System.out.println("3. Comprar billete");
            System.out.println("4. Salir");
            System.out.print("Selecciona una opción: ");
            String opcion = sc.nextLine();

            switch (opcion) {
                case "1" -> registrar(sc);
                case "2" -> listarBilletes();
                case "3" -> comprarBillete(sc);
                case "4" -> {
                    running = false;
                    socket.close();
                }
                default -> System.out.println("Opción inválida");
            }
        }
    }

    /**
     * Registro de un nuevo usuario:
     * - VAlida campos
     * - Genera clave publica del cleitne
     * - Cifra la contraseña RSA usando la clave publica del servidor
     *
     * @param sc
     * @throws Exception
     */
    private void registrar(Scanner sc) throws Exception {
        AuxiliaryClasses.Message msg = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.REGISTER);

        // Solicitar y enviar datos personales
        System.out.print("Nombre: ");
        msg.fields.put("nombre", sc.nextLine());
        System.out.print("Apellido: ");
        msg.fields.put("apellido", sc.nextLine());
        System.out.print("Edad: ");
        msg.fields.put("edad", sc.nextLine());
        System.out.print("Email: ");
        msg.fields.put("email", sc.nextLine());
        System.out.print("Usuario: ");
        msg.fields.put("usuario", sc.nextLine());

        // Validación segura de la contraseña
        String pwd;
        do {
            System.out.print("Contraseña: ");
            pwd = sc.nextLine();
            if (!AuxiliaryClasses.Validator.validatePassword(pwd)) {
                System.out.println("Contraseña insegura: min 8 chars, mayúscula, minúscula y número");
            }
        } while (!AuxiliaryClasses.Validator.validatePassword(pwd));

        // Enviar contraseña cifrada
        msg.fields.put("passwordRaw", pwd);
        msg.fields.put("passwordEncrypted", Base64.getEncoder().encodeToString(AuxiliaryClasses.CryptoUtils.rsaEncrypt(pwd.getBytes(), serverPub)));

        // Generar KeyPair del cliente y guardarlo para compras futuras
        KeyPair kp = AuxiliaryClasses.CryptoUtils.generateRSAKeyPair();
        clientKeyPair = kp;
        // Enviar clave publica al servidor
        msg.fields.put("clientPub", Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()));

        out.writeObject(msg);
        AuxiliaryClasses.Message resp = (AuxiliaryClasses.Message) in.readObject();
        System.out.println(resp.fields.get("msg"));
    }

    /**
     * Solicita al servidor la lista de billetes disponibles
     *
     * @throws Exception
     */
    private void listarBilletes() throws Exception {
        AuxiliaryClasses.Message msg = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.LIST_TICKETS);
        out.writeObject(msg);
        AuxiliaryClasses.Message resp = (AuxiliaryClasses.Message) in.readObject();
        System.out.println("Billetes disponibles:");
        System.out.println(resp.fields.get("list"));
    }

    /**
     * Realiza la comrpa de un billete:
     * - Verifica que el usuario este registrado
     * - Firma digitalmente la transación con su clave privada
     * - Envia los datos al servidor
     * - Simula estado PENDIENTE si el servidor aún no respondió totalmente
     *
     * @param sc
     * @throws Exception
     */
    private void comprarBillete(Scanner sc) throws Exception {
        // Debe existir un par de claves
        if (clientKeyPair == null) {
            System.out.println("Debes registrarte antes de comprar.");
            return;
        }

        System.out.print("ID del billete a comprar: ");
        String ticketId = sc.nextLine();
        if (!ticketId.startsWith("T")) {
            ticketId = "T" + ticketId; // convierte '1' a 'T1'
        }
        System.out.print("Tu usuario: ");
        String usuario = sc.nextLine();

        AuxiliaryClasses.Message msg = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.BUY);
        msg.fields.put("ticketId", ticketId);
        msg.fields.put("usuario", usuario);
        msg.fields.put("nonce", String.valueOf(System.currentTimeMillis())); // evita replay attacks

        // Firmar el mensaje usando la clave privada registrada
        String payload = usuario + "|" + ticketId + "|" + msg.fields.get("nonce");
        msg.signature = AuxiliaryClasses.CryptoUtils.sign(payload.getBytes(), clientKeyPair.getPrivate());

        // Enviar compra
        out.writeObject(msg);
        AuxiliaryClasses.Message resp = (AuxiliaryClasses.Message) in.readObject();

        // Simulación de estado PENDIENTE
        if (resp.fields.get("state") == null) {
            System.out.println("Transacción pendiente, procesando...");
        }

        System.out.println(resp.fields.get("msg"));
    }
}