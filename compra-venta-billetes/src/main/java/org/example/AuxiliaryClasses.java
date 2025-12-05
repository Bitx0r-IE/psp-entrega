package org.example;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.security.PublicKey;

public class AuxiliaryClasses {
    // Clase para mensajes entre cliente y servidor

    static class Message implements Serializable {
        enum Type {REGISTER, REGISTER_RESPONSE, LIST_TICKETS, LIST_RESPONSE, BUY, BUY_RESPONSE, PUBLIC_KEY, ERROR}
        Type type;
        Map<String,String> fields;
        byte[] signature;

        public Message(Type t){
            this.type = t;
            this.fields = new HashMap<>();
        }
    }

// Usuario


    static class User {
        String nombre, apellido, email, usuario;
        int edad;
        byte[] pwdHash;
        byte[] salt;
        PublicKey publicKey;

        public User(String nombre, String apellido, int edad, String email, String usuario, byte[] pwdHash, byte[] salt, PublicKey publicKey){
            this.nombre = nombre;
            this.apellido = apellido;
            this.edad = edad;
            this.email = email;
            this.usuario = usuario;
            this.pwdHash = pwdHash;
            this.salt = salt;
            this.publicKey = publicKey;
        }
    }

    // Ticket
    static class Ticket {
        final String id;
        final String descripcion;
        volatile TicketStatus status;

        public Ticket(String id, String descripcion){
            this.id = id;
            this.descripcion = descripcion;
            this.status = TicketStatus.AVAILABLE;
        }
    }

    enum TicketStatus {AVAILABLE, SOLD}

}
