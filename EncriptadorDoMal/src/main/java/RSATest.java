import java.math.BigInteger;
import java.security.SecureRandom;
/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author AAA
*/
public class RSATest {

  public void RSATest(String msg) {
    //msg = "Paz e felicidade a todos!";
    String msgcifrada = null;
    String msgdecifrada = null;
    BigInteger n, d, e;
    int bitlen = 2048;

    //Escolha de forma aleatória dois números primos grandes p e q
    SecureRandom r = new SecureRandom();
    BigInteger p = new BigInteger(bitlen / 2, 100, r); 
    BigInteger q = new BigInteger(bitlen / 2, 100, r); 

    //Compute n = p * q
    n = p.multiply(q);

    //Compute a função totiente phi(n) = (p -1) (q -1)
    BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

    //Escolha um inteiro  "e"  , 1 < "e" < phi(n) ,  "e" e phi(n) sejam primos entre si.
    e = new BigInteger("3");
    while(m.gcd(e).intValue() > 1) e = e.add(new BigInteger("2"));

    // d seja inverso multiplicativo de "e"
    d = e.modInverse(m);
    
    System.out.println("p:"+p);
    System.out.println("q:"+q);
    System.out.println("n:"+n);
    System.out.println("e:"+e);
    System.out.println("d:"+d);

    //mensagem cifrada - RSA_encrypt()
    msgcifrada = new BigInteger(msg.getBytes()).modPow(e, n).toString();
    System.out.println("msg cifrada: "+ msgcifrada);

    //mensagem decifrada - RSA_decrypt()
    msgdecifrada = new String(new BigInteger(msgcifrada).modPow(d, n).toByteArray());
    System.out.println("msg decifrada: " +msgdecifrada);
    
  }
}

