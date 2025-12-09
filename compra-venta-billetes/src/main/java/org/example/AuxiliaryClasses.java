package org.example;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.security.PublicKey;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;

public class AuxiliaryClasses {
    // Clase para mensajes entre cliente y servidor

    /**
     * Representa los mensaje intercambiados entre cliente y servidor
     * Cada mensaje esta construido con:
     * - un tipo (Type) que indica la operación (en caso de más operaciones que se añadan a las interaccioens cliente servidor, se incluirán más al enum)
     * - un Map de campos clave-valor para enviar datos
     * - una firma digital opcional para operaciones
     */
    static class Message implements Serializable {
        enum Type {REGISTER, REGISTER_RESPONSE, LIST_TICKETS, LIST_RESPONSE, BUY, BUY_RESPONSE, PUBLIC_KEY, ERROR}
        Type type;
        Map<String,String> fields; // Campos del mensaje
        byte[] signature;   // Firma digital para compras

        public Message(Type t){
            this.type = t;
            this.fields = new HashMap<>();
        }
    }

    // Usuario

    /**
     * Ususario registrado en el sistema
     * Contiene los datos personale , credenciales y clave pública para firmas digitales
     */
    static class User {
        String nombre, apellido, email, usuario; // Datos del usuario
        int edad;
        byte[] pwdHash; // hash seguro de la password (PBKDF2)
        byte[] salt; // salt usado para el hash --> salt = valor aleatorio que se usa por la función que realiza el hash a la hora de cifrar datos
        PublicKey publicKey; // Clave públic del usuario para verificar firmas

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

    /**
     * Representa un billete que se puede comprar.
     * Cada billete tiene un ID unico, descripción y estado
     * El estado el volatile para asegurara visbilidad en concurrencia
     */
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

    /**
     * Enum que define el estado de un billete:
     * AVAILABLE: disponible para compra
     * SOLD: ya vendido
     */
    enum TicketStatus {AVAILABLE, SOLD}

    // Validador de campos
    /**
     * Clase para validar los datos ingresados por el usuario.
     * Incluye validación para nombre, apellido, email, usuario, contraseña y edad.
     */
    class Validator {
        // Nombre y apellido: letras y espacios
        private static final String NAME_PATTERN = "^[A-Za-zÁÉÍÓÚÑáéíóúñ ]{2,40}$";


        // Email simple válido
        private static final String EMAIL_PATTERN = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$";


        // Usuario: letras, números, 4-20 chars
        private static final String USER_PATTERN = "^[A-Za-z0-9]{4,20}$";

        // Contraseña: mín. 8 chars, 1 mayúscula, 1 minúscula, 1 dígito
        private static final String PASS_PATTERN = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{8,}$";


        public static boolean validateNombre(String s){ return s != null && s.matches(NAME_PATTERN); }
        public static boolean validateApellido(String s){ return s != null && s.matches(NAME_PATTERN); }
        public static boolean validateEmail(String s){ return s != null && s.matches(EMAIL_PATTERN); }
        public static boolean validateUsuario(String s){ return s != null && s.matches(USER_PATTERN); }
        public static boolean validatePassword(String s){ return s != null && s.matches(PASS_PATTERN); }
        public static boolean validateEdad(String s){
            try {
                int e = Integer.parseInt(s);
                return e >= 18 && e <= 120;
            } catch(Exception ex){ return false; }
        }
    }


    /**
     * Clase para operaciones criptograficas:
     * - Generación de pares de claves RSA
     * - Cifrado y descifrado RSA
     * - Firmas digitales y verificación
     * - Hash seguro de contraseñas con PBKDF2
     */
    public class CryptoUtils {

        // Genera un par de claves RSA
        public static KeyPair generateRSAKeyPair() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            return kpg.generateKeyPair();
        }

        // Cifra datos con clave publica
        public static byte[] rsaEncrypt(byte[] data, PublicKey pub) throws Exception {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            c.init(Cipher.ENCRYPT_MODE, pub);
            return c.doFinal(data);
        }

        // Descifra datps con clave privada
        public static byte[] rsaDecrypt(byte[] data, PrivateKey priv) throws Exception {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            c.init(Cipher.DECRYPT_MODE, priv);
            return c.doFinal(data);
        }

        // Genera una firma digital para los datos
        public static byte[] sign(byte[] data, PrivateKey priv) throws Exception {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(priv);
            sig.update(data);
            return sig.sign();
        }

        // Verifica la firma difital de los datos
        public static boolean verify(byte[] data, byte[] signature, PublicKey pub) throws Exception {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(pub);
            sig.update(data);
            return sig.verify(signature);
        }

        // Genera hash seguro de contraseña usando PBKDF2 con SHA-256 y salt
        public static byte[] pbkdf2(char[] password, byte[] salt) throws Exception {
            PBEKeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return skf.generateSecret(spec).getEncoded();
        }
    }
}
