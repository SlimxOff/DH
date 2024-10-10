import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.math.BigInteger;

public class DHExample {

    public static void main(String[] args) throws Exception {
        // Создаем параметры DH с использованием BigInteger
        BigInteger p = new BigInteger("155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443");
        BigInteger g = new BigInteger("2");
        DHParameterSpec dhParams = new DHParameterSpec(p, g);

        // Создаем сущность A
        Entity entityA = new Entity("A", dhParams);
        // Создаем сущность B
        Entity entityB = new Entity("B", dhParams);

        // Обмен публичными ключами
        entityA.setOtherPublicKey(entityB.getPublicKey());
        entityB.setOtherPublicKey(entityA.getPublicKey());

        // Создаем общий секрет
        entityA.generateSharedSecret();
        entityB.generateSharedSecret();

        // Шифруем сообщение от A к B
        String message = "Hello, B!";
        byte[] encryptedMessage = entityA.encryptMessage(message);
        System.out.println("Encrypted message: " + Base64.getEncoder().encodeToString(encryptedMessage));

        // Дешифруем сообщение на стороне B
        String decryptedMessage = entityB.decryptMessage(encryptedMessage);
        System.out.println("Decrypted message: " + decryptedMessage);
    }

    static class Entity {
        private final String name;
        private final KeyPair keyPair;
        private PublicKey otherPublicKey;
        private SecretKeySpec sharedSecret;

        public Entity(String name, DHParameterSpec dhParams) throws Exception {
            this.name = name;
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(dhParams);
            this.keyPair = keyGen.generateKeyPair();
        }

        public PublicKey getPublicKey() {
            return keyPair.getPublic();
        }

        public void setOtherPublicKey(PublicKey otherPublicKey) {
            this.otherPublicKey = otherPublicKey;
        }

        public void generateSharedSecret() throws Exception {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(keyPair.getPrivate());
            keyAgreement.doPhase(otherPublicKey, true);
            byte[] secret = keyAgreement.generateSecret();
            sharedSecret = new SecretKeySpec(secret, 0, 16, "AES"); // Используем первые 16 байт для AES
        }

        public byte[] encryptMessage(String message) throws Exception {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, sharedSecret);
            return cipher.doFinal(message.getBytes());
        }

        public String decryptMessage(byte[] encryptedMessage) throws Exception {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, sharedSecret);
            byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
            return new String(decryptedBytes);
        }
    }
}