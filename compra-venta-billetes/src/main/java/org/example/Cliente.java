package org.example;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class Cliente {

    private static final String HOST = "127.0.0.1";
    private static final int PORT = 5000;

    public static void main(String[] args) {
        try(Socket socket = new Socket(HOST, PORT);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader console = new BufferedReader(new InputStreamReader(System.in));
            ) {

            System.out.println("Conectando al servidor. Escribe un número o 'salir' para terminar.");

            String mensaje = "";
            System.out.println("Número: ");
            mensaje = console.readLine();

            while(!mensaje.equalsIgnoreCase("salir")) {
                out.println(mensaje);
                String response = in.readLine();
                System.out.println("Respuesta del servidor: " + response);
                System.out.println("Número: ");
                mensaje = console.readLine();
            }

        } catch (IOException e) {
            System.out.println("Error de conexión con el servidor.");
            e.printStackTrace();
        }
    }
}
