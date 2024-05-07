# Cyberthon 2024 - Grogu Petting Simulator (RE)

I created an Android RE challenge for Cyberthon 2024, which was a CTF for Junior College students in Singapore.

The game is designed as a clicker game, where users are required to tap Grogu 10,000 times to get the flag. However, if the user does click through all 10,000 times, they will only be shown a fake flag in the UI. The real flag is stored in the Shared Preferences using a method invoked through reflection. The method's class is found in an encrypted asset file which will be loaded at the start.


# Solution

## Where to start?
There are many ways to solve this challenge, but for this writeup, I will mainly be focusing on pure static analysis. There are many free decompilers like Jadx or JD-GUI, both will be sufficient to solve this challenge.

When reversing Android APKs, there are 5 main entrypoints where you can start your analysis (read more [here](https://www.ragingrock.com/AndroidAppRE/app_fundamentals.html)). In this application, we only need to analyse 2 of the entrypoints since the rest were not implemented.

### 1. Launcher Activity
The launcher activity is the first activity that will be shown to the user when they open the app from their homescreen. We can identify it by finding the activities which registers its `intent-filter` as `"android.intent.action.MAIN"`.
```xml
<activity
  android:exported="true"
  android:name="com.starwars.not.sus.MainActivity">
  <intent-filter>
    <action android:name="android.intent.action.MAIN"/>
    <category android:name="android.intent.category.LAUNCHER"/>
  </intent-filter>
</activity>
```

From `MainActivity`, we can see the `play` function which is the `onClick` handler when we click on the *Next* button. It is responsible of starting the `GameActivity` activity.

```java
public class MainActivity extends AppCompatActivity {
    @Override  // androidx.fragment.app.FragmentActivity
    protected void onCreate(Bundle bundle0) {
        super.onCreate(bundle0);
        this.getWindow().getDecorView().setSystemUiVisibility(4);
        this.setContentView(layout.activity_main);
    }

    public void play(View view0) {
        this.startActivity(new Intent(this, GameActivity.class));
    }
}
```

### 2. GameActivity
Any activity started by the Android System will have their `onCreate` function called implicitly. We quickly realise that this function is responsible for initialising the UI elements of the game. 
```java
public void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    setContentView(R.layout.activity_game);
    final LottieAnimationView lottieAnimationView = (LottieAnimationView) findViewById(R.id.animationView);
    final MaterialTextView materialTextView = (MaterialTextView) findViewById(R.id.tapCount);
    final MaterialTextView materialTextView2 = (MaterialTextView) findViewById(R.id.bodyText);
    materialTextView.setText(String.valueOf(this.Score));
    lottieAnimationView.setFrame(this.YODA_START_FRAME);
    lottieAnimationView.setSpeed(this.YODA_ANIMATE_SPEED);
    lottieAnimationView.setOnClickListener(new View.OnClickListener() { // from class: com.starwars.not.sus.GameActivity$$ExternalSyntheticLambda0
        @Override // android.view.View.OnClickListener
        public final void onClick(View view) {
            GameActivity.this.m209lambda$onCreate$1$comstarwarsnotsusGameActivity(lottieAnimationView, materialTextView, materialTextView2, view);
        }
    });
}
```

Towards the end of the function, we see a lambda method being set as the `OnClickListener` for the `lottieAnimationView`(the Grogu animation in the game). This meant that the method (shown below) will be executed everytime we tap on Grogu.

```java
public /* synthetic */ void m209lambda$onCreate$1$comstarwarsnotsusGameActivity(LottieAnimationView lottieAnimationView, MaterialTextView materialTextView, MaterialTextView materialTextView2, View view) {
    playGroguAnimation(lottieAnimationView);
    int i = this.Score;
    if (i > 0) {
        int i2 = i - 1;
        this.Score = i2;
        materialTextView.setText(String.valueOf(i2));
        if (this.Score == 0) {
            materialTextView2.setText("Flag: " + AppUtils.a(new char[]{' ', 'F', '@', 'I', 'F', 'B', 'I', 'G', '@', 'S', 'H', '_', 'X', '\\', 'D', 'M', 'F', 'E', '\\', 'm', '^', 'Q', 'Y', '_', 'X', 'J', 'P', 'I', 'd', ']', 'X', 'H', 'V', '='}));
            new Thread(new Runnable() { // from class: com.starwars.not.sus.GameActivity$$ExternalSyntheticLambda1
                @Override // java.lang.Runnable
                public final void run() {
                    GameActivity.this.a();
                }
            }).start();
        }
    }
    if (this.Score == 0) {
        ((LottieAnimationView) findViewById(R.id.confettiView)).playAnimation();
    }
}
```

In the if-block of the winning condition, we see that there are 2 lines of code that will be executed. 

The first line decrypts a fake flag and gives it to the user. We can reimplement the string decryption routine in python. You will be using this decryption routine multiple times since most strings in this application are encrypted with this routine.
```python!
def strDecrypt(enc):
    key = ord(enc[0])
    return bytes([ord(c)^(key+i) for i, c in enumerate(enc[1:])])
    
enc = [' ', 'F', '@', 'I', 'F', 'B', 'I', 'G', '@', 'S', 'H', '_', 'X', '\\', 'D', 'M', 'F', 'E', '\\', 'm', '^', 'Q', 'Y', '_', 'X', 'J', 'P', 'I', 'd', ']', 'X', 'H', 'V', '=']
print(strDecrypt(enc)) # b'fakeflag{auspicium_melioris_aevi}'
```

The second line invokes the `GameActivity.a` method on a new `Thread`.

```java
// NOTE: strings in this function have be decrypted 
public void a() {
    try {
        App.StubClass.getMethod("b", Context.class).invoke(null, getApplicationContext());
    } catch (IllegalAccessException | NoSuchMethodException | InvocationTargetException e) {
        throw new RuntimeException(e);
    }
}
```
This method essentially calls the `b` method from the `App.StubClass` object, with `getApplicationContext()` as the argument. This method call is done through Java reflection. 

>**Java reflection** allows us to instantiate new objects and invoke methods of an object at runtime without knowing the names of the interfaces, fields, methods at compile time. In a way, its similar to linux's `dlopen` and `dlsym` or Windows's `LoadLibrary` and `GetProcAddress`

But how was the `App.StubClass` object created? Remember I mentioned that there was another entrypoint that we have yet to analyse? 

### 3. Application Subclass
If an Android app defines a Application subclass, this class will be the first class to be instantiated. The `attachBaseContext` method defined in the subclass will be called first, followed by the `onCreate` method. To identify which is the subclass, we can check the manifest file. The subclass is defined in the `android:name` field.
```xml
<application 
    android:theme="@style/Theme.Sus" 
    android:label="@string/app_name" 
    android:icon="@mipmap/ic_launcher" 
    android:name="com.starwars.not.sus.App" 
    android:allowBackup="true" 
    android:supportsRtl="true" 
    android:extractNativeLibs="false" 
    android:fullBackupContent="@xml/backup_rules" 
    android:roundIcon="@mipmap/ic_launcher_round" 
    android:appComponentFactory="androidx.core.app.CoreComponentFactory" 
    android:dataExtractionRules="@xml/data_extraction_rules">
```

This is the subclass that extends `Application`.
```java
// NOTE: All encrypted strings have been decrypted
public class App extends Application {
    public static Class StubClass;

    private File a() {
        try {
            File file0 = File.createTempFile("temp", null, this.getCacheDir());
            InputStream inputStream0 = this.getAssets().open("sys");
            SecretKeySpec secretKeySpec0 = new SecretKeySpec("what_is_this_file".getBytes(StandardCharsets.UTF_8), "RC4");
            Cipher cipher0 = Cipher.getInstance("RC4");
            cipher0.init(2, secretKeySpec0);
            CipherInputStream cipherInputStream0 = new CipherInputStream(inputStream0, cipher0);
            FileOutputStream fileOutputStream0 = new FileOutputStream(file0);
            byte[] arr_b = new byte[0x400];
            while(true) {
                int v = cipherInputStream0.read(arr_b);
                if(v == -1) {
                    break;
                }

                fileOutputStream0.write(arr_b, 0, v);
            }

            cipherInputStream0.close();
            fileOutputStream0.close();
            file0.setReadOnly();
            return file0;
        }
        catch(IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException unused_ex) {
            return null;
        }
    }

    @Override  // android.content.ContextWrapper
    protected void attachBaseContext(Context context0) {
        super.attachBaseContext(context0);
        this.b();
    }

    private void b() {
        File file0 = this.a();
        try {
            App.StubClass = new DexClassLoader(file0.getAbsolutePath(), this.getFilesDir().getAbsolutePath(), null, this.getClassLoader()).loadClass("a.a.b");
            file0.delete();
            return;
        }
        catch(Exception exception0) {
            throw new RuntimeException(exception0);
        }
    }
}
```

Analyzing this class, we see that it
1. Opens `sys` file from the `assets` directory
2. Decrypts the file using `RC4` algorithm with the key: `what_is_this_file`
3. Loads the `a.a.b` class from the decrypted dex file using `DexClassLoader` and assigns it to the static field `App.StubClass`
4. Deletes the decrypted dex file.


We can decrypt the `sys` file using CyberChef to obtain a dex file.


### 4. Encrypted Dex 
Recall earlier in the threaded call, we try to invoke the `b` method from `App.StubClass` in `GameActivity`? The implementation of that function is in this dex file.
```java
public class b {
    private static String ENCRYPTION_IV;
    private static String ENCRYPTION_KEY;
    private static String ENCRYPTION_KEY_SALT;

    static {
        b.ENCRYPTION_KEY = "grogu123";
        b.ENCRYPTION_KEY_SALT = "aS3w24fA";
        b.ENCRYPTION_IV = "f17MF4e5YoTWa7EX";
    }

    public b() {
        super();
    }

    public static void b(Context ctx) {
        try {
            String s = b.decrypt("XaWNi/j09rs87U/bB2gf3I7SLwjSphbt4gwHflF2TvvDxTkIRwSZjeaWaVPpXHGn", b.generateKey(b.ENCRYPTION_KEY, b.ENCRYPTION_KEY_SALT.getBytes(StandardCharsets.UTF_8)));
            SharedPreferences.Editor sharedPreferences$Editor0 = ctx.getSharedPreferences("Info", 0).edit();
            sharedPreferences$Editor0.putString("flag", s);
            sharedPreferences$Editor0.commit();
            return;
        }
        catch(Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String decrypt(String enc, SecretKey key) throws Exception {
        Cipher cipher0 = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher0.init(2, key, new IvParameterSpec(b.ENCRYPTION_IV.getBytes("UTF-8")));
        return new String(cipher0.doFinal(Base64.getDecoder().decode(enc)));
    }

    private static SecretKey generateKey(String pw, byte[] salt) throws Exception {
        return new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(pw.toCharArray(), salt, 0x10000, 0x100)).getEncoded(), "AES");
    }
}
```

The `b` method decrypts a string using AES CBC algorithm, and stores it inside the application's Shared Preferences. We can get the actual flag by reimplementing the decryption logic in python (or just copy and run the java code).

```python
from hashlib import pbkdf2_hmac
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

enc = "XaWNi/j09rs87U/bB2gf3I7SLwjSphbt4gwHflF2TvvDxTkIRwSZjeaWaVPpXHGn"
ENCRYPTION_KEY = b"grogu123"
ENCRYPTION_KEY_SALT = b"aS3w24fA"
ENCRYPTION_IV = b"f17MF4e5YoTWa7EX"
key = pbkdf2_hmac(
    hash_name = 'sha256',
    password = ENCRYPTION_KEY,
    salt = ENCRYPTION_KEY_SALT,
    iterations = 65536,
    dklen = 32
)
ct = b64decode(enc)
cipher = AES.new(key, AES.MODE_CBC, ENCRYPTION_IV)
pt = unpad(cipher.decrypt(ct), AES.block_size).decode()
print(pt)
```
Flag: `Cyberthon{4r3_y0ur_f1ng3rs_t1r3d}`