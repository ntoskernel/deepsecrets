# PAY.JP for Java

[![Build Status](https://travis-ci.org/payjp/payjp-java.svg?branch=master)](https://travis-ci.org/payjp/payjp-java)

Requirements
============

Java 1.6 and later.

Installation
============

### Maven users

Add this dependency to your project\'s POM:

```xml
<dependency>
  <groupId>jp.pay</groupId>
  <artifactId>payjp-java</artifactId>
  <version>0.1.0</version>
</dependency>
```

### Gradle users

Add this dependency to your project\'s build file:

```groovy
compile "jp.pay:payjp-java:0.1.0"
```

### Others

You\'ll need to manually install the following JARs:

* The Payjp JAR from https://github.com/payjp/payjp-java/releases/latest
* [Google Gson](http://code.google.com/p/google-gson/) from <http://google-gson.googlecode.com/files/google-gson-2.2.4-release.zip>.
* [javax.mail](http://www.oracle.com/technetwork/java/javamail/index.html) from <http://central.maven.org/maven2/javax/mail/mail/1.4.7/mail-1.4.7.jar>

### [ProGuard](http://proguard.sourceforge.net/)

If you\'re planning on using ProGuard, make sure that you exclude the Payjp bindings. You can do this by adding the following to your `proguard.cfg` file:

    -keep class jp.pay.** { *; }

Usage
=====

PayjpExample.java

```java
import java.util.HashMap;
import java.util.Map;

import jp.pay.Payjp;
import jp.pay.exception.PayjpException;
import jp.pay.model.Charge;
import jp.pay.net.RequestOptions;

public class PayjpExample {

    public static void main(String[] args) {
        Payjp.apiKey = "sk_test_a23maot6a746c40cd76d7036";
        Map<String, Object> chargeMap = new HashMap<String, Object>();
        chargeMap.put("amount", 3500);
        chargeMap.put("currency", "jpy");
        Map<String, Object> cardMap = new HashMap<String, Object>();
        cardMap.put("number", "4242424242424242");
        cardMap.put("exp_month", 12);
        cardMap.put("exp_year", 2020);
        chargeMap.put("card", cardMap);
        try {
            Charge charge = Charge.create(chargeMap
);
            System.out.println(charge);
        } catch (PayjpException e) {
            e.printStackTrace();
        }
    }
}
```

Testing
=======

You must have Maven installed. To run the tests, simply run `mvn test`. You can run particular tests by passing `-D test=Class#method` -- for example, `-D test=PayjpTest#testChargeCreate`.
