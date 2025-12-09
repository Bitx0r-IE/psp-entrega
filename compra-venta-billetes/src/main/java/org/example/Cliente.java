package org.example;

import org.example.AuxiliaryClasses;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Cliente {

    private Socket socket;
    private ObjectOutputStream out;
    private ObjectInputStream in;
    private PublicKey serverPub;

    public Cliente(String host, int port) throws Exception {
        socket = new Socket(host, port);
        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());

        // Recibir clave pública del servidor
        AuxiliaryClasses.Message msg = (AuxiliaryClasses.Message) in.readObject();
        if (msg.type == AuxiliaryClasses.Message.Type.PUBLIC_KEY) {
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

    private void registrar(Scanner sc) throws Exception {
        AuxiliaryClasses.Message msg = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.REGISTER);
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
        System.out.print("Contraseña: ");
        String pwd = sc.nextLine();

        // Enviar contraseña cifrada
        msg.fields.put("passwordRaw", pwd);
        msg.fields.put("passwordEncrypted", Base64.getEncoder().encodeToString(AuxiliaryClasses.CryptoUtils.rsaEncrypt(pwd.getBytes(), serverPub)));

        // Generar clave pública propia para el ejemplo
        KeyPair kp = AuxiliaryClasses.CryptoUtils.generateRSAKeyPair();
        msg.fields.put("clientPub", Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()));

        out.writeObject(msg);

        AuxiliaryClasses.Message resp = (AuxiliaryClasses.Message) in.readObject();
        System.out.println(resp.fields.get("msg"));
    }

    private void listarBilletes() throws Exception {
        AuxiliaryClasses.Message msg = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.LIST_TICKETS);
        out.writeObject(msg);
        AuxiliaryClasses.Message resp = (AuxiliaryClasses.Message) in.readObject();
        System.out.println("Billetes disponibles:");
        System.out.println(resp.fields.get("list"));
    }

    private void comprarBillete(Scanner sc) throws Exception {
        System.out.print("ID del billete a comprar: ");
        String ticketId = sc.nextLine();
        System.out.print("Tu usuario: ");
        String usuario = sc.nextLine();

        AuxiliaryClasses.Message msg = new AuxiliaryClasses.Message(AuxiliaryClasses.Message.Type.BUY);
        msg.fields.put("ticketId", ticketId);
        msg.fields.put("usuario", usuario);
        msg.fields.put("nonce", String.valueOf(System.currentTimeMillis()));

        // Firmar mensaje (para el ejemplo generamos un KeyPair temporal)
        KeyPair kp = AuxiliaryClasses.CryptoUtils.generateRSAKeyPair();
        msg.signature = AuxiliaryClasses.CryptoUtils.sign((usuario + "|" + ticketId + "|" + msg.fields.get("nonce")).getBytes(), kp.getPrivate());

        out.writeObject(msg);
        AuxiliaryClasses.Message resp = (AuxiliaryClasses.Message) in.readObject();
        System.out.println(resp.fields.get("msg"));
    }
}
