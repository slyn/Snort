

# I. BİLİNMESİ GEREKEN TEMEL KAVRAMLAR

## A. Simgeler ve Kısaltmalar

Bu çalışmada kullanılan kısaltmaların, açıklamaları aşağıda verilmiştir.

|Kısaltmalar| Açıklama                |
|:---------:|:-----------------------|
|STS        |Saldırı Tespit Sistemi   | 
|SES        |Saldırı Engelleme Sistemi|
|IDS        |Intrusion Detection System|
|IPS        |Intrusion Protection System|
|ACID       |Analysis Console for Intrusion Databases|
|NIDS       |Network Based Intrusion Detection Systems|
|HIDS       |Host Based Intrusion Systems |
|RAM        |Random Access Memory |
|IP         |Internet Protocol |
|CDIR       |Class Inter-Domain Routing|
|ISP        |Internet Service Provider| 
|LAN        |Local Area Network| 
|PDP        |Packet Data Protocol|
|TCP        |Transmission Control Protocol |
|DMZ        |DeMilitarized Zone |
|SNMP       |Simple Network Managment Protokol|
|ICMP       |Internet Control Message Protocol|
|CGI        |Common Gateway Interface|
|IDPS       |Intrusion Detection and Prevention System|
|BASE       |Basic Analysis and Security Engine|
|SMB        |Server Message Block|
**(KILIÇ, OCAK - 2013)**

## B. Saldırı Tespit Sistemleri (STS)

<p>Hızla büyüyen siber dünya, işlerimizi kolaylaştırması sebebiyle değişik formlarda 
yaşantımıza girmeyi başardı. E-devlet, e-ticaret, e-imza gibi kavramlar hız ve verimliliği sebebiyle 
çok fazla duyulmaya başlandı ve beraberinde de ağ ve bilgi güvenliği kavramlarına da teknolojik 
ve hukuki katkıda bulundu.</p>

<p>Teknolojik olarak bilginin tehdit ve saldırılara karşı korunması için güvenlik duvarları, STS
ve SES araçlar geliştirildi. Bu araçları doğru şekilde yapılandırarak ağ ve bilgi güvenliğimizi büyük 
ölçüde sağlayabiliriz.</p>


<p>Peki, büyüyen siber dünya ile beraber gelen bu STS nedir? STS yani saldırı tespit sistemleri, 
bilginin elektronik ortamlarda taşınırken, işlenirken veya depolanırken başına gelebilecek tehlike ve 
tehditlerin ortadan kaldırılması veya bunlara karşı tedbir alınması amacıyla, bilgiye yetkisiz erişim ve 
bilginin kötüye kullanılması gibi internet veya yerel ağdan gelebilecek çeşitli paket ve verilerden oluşan 
girişimleri tespit edebilme, bu tespitleri sms, e-posta veya SNMP mesajları ile sistem güvenliğinden 
sorumlu kişilere iletebilme ve gerektiğinde paketi/erişimi düşürebilme özelliğine sahip yazılımsal 
ve/veya donanımsal güvenlik araçları olarak tanımlanabilir. (KAYA & ERDEM, 2014)</p>

STS’ler aşağıdaki kriterler başta olmak üzere değişik ölçütlere göre sınıflandırılabilir:

* Veri İşleme Zamanına Göre
    * Gerçek Zamanlı (REAL TIME)
    * Gerçek Zamanlı Olmayan (BATCH)

* Mimari Yapısına Göre
    * Çok sayıda STS’den veri toplayıp bir yerde verileri işlemek
    * Tek kaynaktan veri toplayıp aynı yerde verileri işlemek

* Bilgi Kaynağına Göre
    * Ağ temelli
    * Sunucu temelli
    * Uygulama temelli

* Veri İşleme Yöntemine Göre
    * Anormallik tespiti temelli
    * İmza Temelli

**(EROL)**
<p>En çok tercih edilen sınıflandırma kriteri veri işleme yöntemine göre sınıflandırmaktır. Veri 
işleme yöntemi de kendi içinde Anormallik tespiti temelli ve imza temelli olmak üzere ikiye ayrılır.
Anormallik tespitinde normal davranışlar belirlenir ve bu belirlenen davranışlar dışındaki tüm 
davranışlar tehdit olarak algılanır. Bu yöntem bizi yeni geliştirilen saldırı tekniklerine karşı 
korumaya alabilirken, diğer taraftan da çok fazla yanlış alarm üretmektedir. İmza temelli ise her 
davranışın kendine has karakterini temel alır. Daha önceden saldırı imzası sisteme tehdit unsuru 
olarak kaydedilmiş ise sistem tekrar aynı imza ile karşılaşınca tehdidi tespit edebilir. Eğer yeni 
geliştirilmiş bir saldırı tekniği ise sistem bunu tehdit unsuru olarak algılamaz.</p>

## C. Saldırı Tespit Sistemlerinde Kullanılan Yöntemler

<p>STS’lerin geliştirilmesinde günümüze kadar istatistiksel yöntemlerin dışında, kural tabanlı 
(rule based), eşik değeri belirleme (threshold value), durum geçiş diyagramları (state transition 
diagrams), yapay sinir ağları (artificial neural networks), veri madenciliği (data mining), yapay 
bağışıklık sistemi (artificial immune system), bulanık mantık (fuzzy logic) gibi farklı birçok 
yaklaşım uygulanmıştır**(GÜVEN & SAĞIROĞLU, 2008)**.</p>

## D. Kaçak Giriş Tespit ve Engelleme Sistemleri (IDS/IPS)

<p>IDS genel olarak saldırı tespit sistemidir. Bu sistemde ağ trafiği dinlenir ve daha önceden 
belirlenmiş güvenlik kurallarıyla uyuşmayan paketleri tespit edilir. Şüpheli olarak tespit edilmiş 
paket için IDS gerekli yerlere uyarı verebilir. IDS, şüpheli davranışların tespiti, kayıt altına alınması
ve analizinde kullanılır.</p>

<p>IPS genel olarak saldırı engelleme sistemidir. IDS gibi çalışır ama şüpheli davranışları kayıt 
altına almadan ve analiz yapmadan engelleme yapar. Paketlerin sistemdeki hedef makinaya 
ulaşmasını engeller.</p>

<p>IDS ve IPS genellikle tek başlarına kullanılmaz. IDPS olarak saldırı tespit ve engelleme 
sistemi olarak beraber kullanılır. Bunun için en iyi örnek 'SNORT' olarak gösterilebilir. Yazının 
ilerleyen kısımlarından bundan bahsedeceğiz ama şimdi IDS türlerinden, saldırı tespit sistemlerinin 
daha verimli çalışması için ağ topolojisinde bulunması gereken konumundan ve yanlış alarm 
üretmemesi için yapılması gerekenlerden bahsedelim.</p>

<p>İki temel IDS türü vardır. Bunlardan ilki NIDS yani Network tabanlı IDS. Bütün ağı dinler 
ve tüm sistemlere gelen – giden paketleri inceleyerek analiz yapar. HIDS (Host tabanlı IDS) ise 
diğer IDS türüdür. HIDS herhangi bir istemci ya da sunucuya kurulur sisteme gelen – giden 
saldırılardan haberdar olunmasını sağlar.</p>

 <p>Saldırı tespit sitemlerinin konumu tamamen kendi network topolojimize bağlıdır. İstersek 
birden fazla yerde de konumlandırabileceğimiz gibi aynı zamanda iç ağda mı yoksa dış ağda mı 
saldırıları belirleyeceğimize de bağlıdır. Örneğin sadece dış saldırı hareketlerini belirleyeceksek ve 
tek bir routerımız varsa IDS için en uygun yer routerın içi veya firewalldur. Eğer birden fazla 
internet girişimiz olsaydı her girişe bir IDS kutusu konulması gerekecekti.</p>

<p>IDS, sistemimizi yapılan saldırılara karşı korurken aynı zamanda sistemin güvenliği için 
kendisini de korumalıdır. Saldırgan sisteme atak yapmadan önce saldırı tespit sistemimizi 
kapatabilir, yanlış alarm ya da hiç alarm üretmeyecek şekilde ayarlarını bozabilir. Böyle bir durumla 
karşılaşmamak için aşağıdaki adımları IDS sisteminize uygulayarak sistemin güvenliğini daha da 
artırabiliriz: </p>
  * IDS sensör üzerinde başka hiçbir servis çalıştırılmamalıdır.
  * Yeni açıklıklar bulunup güncelleştirmelerle kapatıldığı zaman Snort’un üzerinde çalıştığı 
makinaya da bu güncelleştirmeler yüklenmelidir.
  * IDS makinasının yapılandırılması ping isteğine yanıt vermeyecek şekilde 
yapılandırılmalıdır.
  * Eğer snort, linux makine üzerinde çalışıyorsa, netfilter/iptable ile istenmeyen paketler
engellenir.
  * IDS sadece saldırı tespit için kullanılmalı başka işlemler için kullanılmamalıdır.

## E. Snort ve Bileşenleri 

### Snort 

<p>Snort, açık kaynak ağ tabanlı bir IDS'tir. 4.000.000’dan fazla indirme ve yaklaşık olarak 
500.000 civarında kayıtlı kullanıcı sayısı ile en fazla tercih edilen saldırı tespit sistemidir. Gerçek 
zamanlı ağ trafik analizi ve paket loglaması yapabilir. Ağdan dinlediği paketlerde protokol ve içerik 
analizi yaparak saldırıları tespit eder. Buffer overflow, port tarama, CGI saldırı gibi hareketleri 
tespit edebilir.</p>

<p>Snort farklı bileşenlerden oluşur ve bu bileşenler beraber çalışarak saldırıları belirler ve çıktı 
üretirler. Snort tabanlı IDS sistemleri başlıca şu bileşenlerden oluşur:</p>

* Packet Decoder
* Preprocessors
* Detection Engine
* Logging and Alerting System
* Output Modules

Bu bileşenlerin çalışma mimarisi aşağıdaki resimdeki gibidir.

![Snort Mimarisi](RESIM MIMARISI.png)

### Packet Decoder:
Ağ ara yüzünden çeşitli tiplerdeki paketleri alır ve bir sonraki snort bileşeni için hazırlar.

### Preprocessors:
Detection Engine' den önce paketleri ona hazırlar ve paket başlıklarındaki anormalliklere göre saldırı belirlemeye çalışır. Preprocessor genellikle parça parça gelen büyük veri parçalarını bir araya getirmek için çalışır.

### Detection Engine:
Snort’un en önemli bileşenlerinden birisidir. Paket içindeki saldırı türlerini belirlemekten sorumludur. Bu saldırıları tespit etme noktasında da snort kurallarını kullanmaktadır. Snort kurallarında belirtilmiş bir saldırı işareti ile preprocessor bileşeninden gelen paket içeriği karşılaştırılır ve tehlikeli bir durum varsa kural başlığında yer alan eylem gerçekleştirilmek için bir sonraki modüle geçilir.

### Logging and Alerting System:
Detection engine bileşeni paket içeriğinin hangi kural ile örtüştüğünü tespit etikten sonra kural başlığında belirtilen eyleme göre loglama, uyarı verme gibi işlemler yapar. Loglar tcpdump veya daha başka bir dosya formatında basit bir yazı dosyasına kaydedilebilir. Snortun çalışması için verilen komutta -l parametresi ile loglama yapılacak dizin de belirtilebilir.

### Output Modules:
Detection engine bileşeninin çıktılarını yönlendirmemizi veya başka şekillerde kullanmamızı sağlar. Başlangıç olarak genellikle çıktılar /var/log/snort dizinine kaydedilir. Bu modül kullanılarak elde edilen çıktı başka bir hedefe de gönderilebilir.

   Output veya 'Logging and alerting system' bileşenleri sayesinde üretilen çıktı aşağıdaki şekillerde kullanılabilir.

•	Veri Tabanına Kayıt Etmek:

<p>Snort loglarını veri tabanda sistematik bir şekilde tutabiliriz. Örneğin snort çıktılarını bir MySQL veri tabanında tutacağız. Veri tabanın ismi snort olsun kullanıcı adı ‘snort’, şifresi de ‘test’ olsun ve veri tabanı yerel makinada bulunsun. Bu durumda snort.conf dosyasında aşağıdaki gibi bir bildirim bulunmalıdır.</p>

```output database: log, mysql, user=snort password=test dbname=snort host=localhost```

•	SMB pop-up olarak Windows' a göndermek:

```output alert_smb: workstation.list```

•	Hem SMB Windows’ a göndermek hem de veri tabanına kayıt etmek:
<p>
Bazen çıktıların birden fazla yere bildirilmesi gerekebilir. Böyle bir durumda ruletype anahtar kelimesiyle eylemimizi belirleyebiliriz. Örneğin snort.conf dosyasında *'smb_db_alert'* olarak belirlediğimiz bir eylem tipi hem veri tabanına kayıt yapıp hem de SMB pop-up uyarısı verecektir. Bunun için aşağıdaki gibi bir bildirim yapılmalıdır.</p>

```
 ruletype smb_db_alert
   {
  	  type alert
  	  output alert_smb: workstation.list
  	  output database: log, mysql, user=snort password=test dbname=snort host=localhost
   }
```

Bu belirlenen aksiyon tipini snort kurallarında kullanırken de aşağıdaki şekilde kullanılır.

```smb_ddb_alert icmp any any -> 192.168.1.0/24 any (fragbits: D; msg: "Dont Fragment bit set";)```

## F. Snort Platformları

Snort birçok işletim sistemi ve donanım üzerinde çalışabilir. Aşağıdakiler de bunlardan bazılarıdır:
*	Linux
*	OpenBSD
*	FreeBSD
*	NetBSD
*	Solaris
*	HP-UX
*	AIX
*	IRIX
*	MacOS
*	Windows

## G. Çalışma Şekilleri

Snort şu üç faklı şekilde çalışması için yapılandırılabilir:

*  Paket İzleme Modu (Packet Sniffing): Ağdan almış olduğu paketleri olduğu gibi tcpdump formatında konsol ekranında gösterir. Bunun için komut olarak *“snort -v ”* kullanılır.

*  Paket Günlükleme Modu (Packet Logger): Ağdan almış olduğu paketleri belirtilmişş olan dizine kaydeder. Bunun için *”snort -dev -l /var/log/snort”* komutu kullanılır ve paketler belirtilen dizine kaydedilir.

* Ağ Sızma Tespit/Engelleme Sistemi Modu (NIDS/NIPS): Snortun en karmaşık modudur. Snort ağı dinlerken daha önceden belirlenmiş kuralları da uygular. *”snort -dev -l ./log -h 192.168.1.0/24 -c snort.conf “* komutu ile snort.conf dosyasında belirtilen kurallara göre işlem yapar. **(Bir Ağ Güvenlik Aracı Olarak SNORT, -)**

## H. Snort İle Kullanılan Eklentiler
   
**BARNYARD:** Snort’ un ağ dinlerken tuttuğu kayıtların belirli bir şablon dahilinde veri tabanına yazılmasını sağlar. 

**ADODB:** Veri tabanı ile BASE arasındaki bağlantıyı sağlar.

**BASE:** Barnyard’ın veri tabanına yazdığı snort kayıtlarını, bir web ara yüzünden daha anlaşılır şekilde grafiksel tablolar ile kullanıcıya sunulmasını sağlar.

**OINKMASTER:** Snort kurallarını düzenlemek için hazırlanmış kullanıcıların işini kolaylaştıran bir araçtır.

**PULLEDPORK:** Snort kuralları güncellendiği zaman sistemimizdeki snort kurallarını da güncelleyen kullanıcıların işini kolaylaştıran bir araçtır.

**SNORTSAM:** Güvenlik duvarında otomatik olarak IP engellemesi yapılmasını sağlayan bir snort eklentisidir.

**ACID:** Saldırı tespit sistemleri tarafından veri tabanına yazılmış verileri alıp işleyip bir web ara yüzünde kullanıcıya sunmayı sağlayan bir PHP tabanlı analiz aracıdır.

**SNORBY:** Güvenlik durumunu izlemeyi sağlayan ruby on rails ile geliştirilmiş bir web uygulamasıdır. Populer IDS’ler ile beraber çalışabilir.

--------------------------------------------------------------

# II. SNORT KURALLARI VE KURAL YAZIMI

<p>Snort’u başarılı bir şekilde kurduktan sonra Snort önceden belirlenmiş kuralları temel alarak sisteme gelen giden paketleri inceler ve buna göre alarm üretip loglama yapar. Snort tarafından üretilen bu alarmların doğrularının yanında yanlış olarak verilmiş alarmlar da vardır. Gerçek saldırılar bu şekilde gözden kaçabilir böyle bir durumla karşılaşmamak için snort kuralları yazılırken çok dikkatli olunmalıdır.</p>

<p>Source Fire tarafından yayınlanan güncel kurallar www.snort.org sitesinden takip edilerek sistem güncel tutulmalıdır. Source Fire firması yeni bulunan herhangi bir saldırı yöntemi, sistem açığı gibi güvenliğimizi tehdit eden durumlarda derhal yeni kurallar yazıp abone olan snort kullanıcılarını bu durumdan haberdar eder. Firmanın yayınlamış olduğu kuralları bedavaya kullanmak isteyen kayıtlı kullanıcılar ise yaklaşık olarak her ay güncellenen kuralları indirip kullanabilir. Bu şekilde kayıtlı kullanıcılar güncel kural takibinde 30 gün geriden gelmektedir.</p>

<p>Snort, çok fazla yanlış alarm üretiyorsa sağlıklı bir saldırı tespiti yapmak için kuralları gözden geçirmek gerektir. Kuralları kendi sistemimize göre ayarlarken sistemimizde açık oluşturmamaya dikkat etmeliyiz ve bu kural düzenleme işinde Oinkmaster aracını kullanarak işimizi kolaylaştırabiliriz.</p>

<p>Kural yazması hem çok kolay hem de saldırıları tespit etmede başarılıdır. Kural yazmaya başlamadan önce örnek bir snort kuralı inceleyerek snort kurallarının genel yapısı hakkında bilgi sahibi olalım. Örnek olarak aşağıdaki gibi bir kuralı inceleyebiliriz.</p>

![KURAL](Kuralgrafigi)

<p>Snort kuralları kural başlığı ve kural seçeneği olmak üzere iki kısımdan oluşur. Kural başlığı kural eylemi, kural protokolü, hedef ve kaynak ip adresleri ile hedef ve kaynak port bilgilerini bulundurur. Diğer kısım ise hangi durumda belirlenen eylemin gerçekleşeceğini ve alarm mesajı ile ilgili özelliklerin tanımlandığı alanları içerir. Parantez işaretine kadar olan kısım kural başlığını (rule header) oluşturur ve her kuralda bulunması gereken kısımdır. Parantez içerisindeki kısım ise kural seçeneğini (rule options) oluşturur.</p>

## A. Kural Başlığı
* **Kural Eylemi**
Kural eylemi kuralın en başında bulunan, belirlenen durumla karşılaşılınca ne yapılacağını belirleyen kısımdır. Snortta bunun için kullanılabilecek başlıca eylemler şunlardır: 

**alert:** belirlenen şekilde alarm üretir ve paketi loglar.

**log:** paketi direk olarak loglar.

**pass:** paketi geçirir paket için herhangi bir alarm ya da loglama işlemin de bulunmaz.  

**drop:** paketi engeller ve kaydeder.

**reject:** paketi engeller, kaydeder ve protokole göre hata mesajı üretir. Örneğin, UDP protokolü kullanılıyor ise ICMP porta ulaşılamadı hata mesajı gönderir.

**sdrop:** paketi engeller ve kaydetmez.

Ayrıca, Snort’un output modülünde de anlatılmış olan ruletype ile kendimize göre kural eylemleri üretebiliriz.

* **Protokoller**
<p>Hangi protokole sahip paketlerin incelemeye alınacağını belirlemek için kullanılır, kural başlığında ikinci sırada bulunur. Snort’ un şu anda güncel olarak saldırı belirlemesi yapabildiği dört protokol vardır. Bunlar TCP, UDP, ICMP ve IP protokolleridir. İlerleyen zamanlarda belki de ARP, IGRP, GRE, OSPF, RIP, IPX gibi protokolleri de kullanabiliyor olacağız.</p>

* **IP Adresleri**
<p>Örnek kuralda *$EXTERNAL_NET* ve *$HOME_NET* yazan kısımlardır ve bu kısımlar aşağıdaki gibi olabilir hatta buralara 192.168.1.5 veya 192.1.0/24 gibi IP adresi ve CIDR blok da yazılabilir. Ayrıca, hariç tutmak için kullanılan ‘!’ operatörü de bu kısımlarda kullanılabilir.</p>

```alert tcp !192.168.1.0/24 any -> 192.168.1.0/24 any (content: “ICERIK”; msg: “DIŞ AĞDAN”;)```

* **Port Adresleri**
<p>Port adreslerini, özel olarak belli bir yolu dinlemek için kullanırız. Port numaraları için ayrılmış olan kısımlar daha önceden yazmış olduğumuz kural örneklerinde “any” olarak yazdığımız bölümlerdir. Bu kısımlara 80, 21, 22 gibi port numaraları girerek daha spesifik kurallar da oluşturabiliriz. Çeşitli şekillerdeki kullanımlarını görmek için aşağıdaki kural örneklerini inceleyebiliriz.</p>

|KURAL|FONKSIYONU|
|:---:|:--------:|
|log udp any any -> 192.168.1.0/24 1:1024|Belirlenen IP aralığındaki herhangi bir makinenin 1 ile 1024 arasında değişen numaralı portlarına gönderilmiş udp protokolünü kullanan herhangi bir IP adresi ve portundan gelen bütün paketleri loglar|
|log tcp any any -> 192.168.1.0/24 :6000|TCP protokolünü kullanan ve belirlenen IP aralığında 6000 ve daha düşük numaraya sahip portları hedef alan herhangi bir IP ve porttan gönderilmiş bütün paketleri loglar|
|log tcp any :1024 -> 192.168.1.0/24 500:|Herhangi bir IP den belirlenen IP aralığına giden, TCP protokolünü kullanan ve 1024 numaralı porta kadar olan herhangi bir porttan 500 numaralı ve üzerindeki portları hedef alan paketleri loglar|
|log tcp any any -> 192.168.1.0/24 !6000:6010|TCP protokolünü kullanan herhangi bir porttan ve herhangi bir IP’ den belirlenen IP aralığına ve 6000 hariç 6010 numaralı porta kadar olan portları hedef alan paketleri loglar|
**(Writing Snort Rules , -)**

* **Yön Operatörü**
<p>İncelenecek olan paketlerin iletim yönünü belirlemek için kullanılır. Bizim sistemimizden çıkan paketleri mi yoksa bizim sistemimize gönderilen paketlerimi inceleceğimizi belirleyebilmek için kullanırız. Üç faklı yön belirleme yöntemi bulunur. Bunlar ‘->’, ‘<-‘, ‘<>’ şeklindedir.</p>

## B. Kural Seçenekleri
<p>Kural seçenekleri, Snort kurallarına esneklik ve güç kazandırır aynı zamanda bu kuralların en önemli parçasıdır. Kural seçenekleri kısmı oluşturulurken her yazılmış parametreden sonra ‘;’ karakteri konulur. Genellikle snort kurallarında kullanılan başlıca kural seçenekleri aşağıdakilerden oluşmaktadır:</p>

* msg: alarma ve kaydedilen paket için mesaj yazar.
* logto: standart log tutulan dosya yerine özel belirlenmiş dosyaya paketi kaydetmek için kullanılır.
* ttl: IP başlığındaki TTL değerini test etmek için kullanılır.
* id: IP başlığındaki ID değerini test etmek için kullanılır.
* content: paket içeriğindeki değeri incelemek için kullanılır.
* offset: content parametresinin neresinden incelenmeye başlayacağını söylemek için kullanılır.
* depth: içeriğin ne kadar derinlemesine inceleneceğini düzenlemek için kullanılır.
* within: ilk content parametresinden sonra ne kadar byte içerisinde diğer content parametresi aranacağını söylemek için kullanılır.
* flags: TCP bayraklarını kesin değer için test eder.
* seq: TCP sequence number kısmını test etmek için kullanılır.
* ack: TCP acknoledgement alanını test etmek için kullanılır.
* itype: ICMP type alanı için karşıt bir değer belirlemekte kullanılır.
* icode: ICMP code alanı için karşıt bir değer belirlemekte kullanılır.
* session: uygulama katmanı için kullanılır.
* sid: eşsiz, tek snort kuralı tanımlaması yapabilmek için kullanılır. Genellikle ‘rev’ ile kullanılır. 
      * 100’den küçük sayılar gelecekte kullanılmak için ayrılmıştır.
      * 100-999,999 Aralığını snort dağıtımı ile beraber gelen kurallar kullanır.
      * 1,000,000 ve yukarısı yerel kurallar için kullanılır.
* rev: snort kuralı revizyonlarının sayısıdır. Sid ile beraber kullanılır. 
* classification: kuralı snıflandırmak için kullanılır.
* priority: kurala önem derecesi tanımlamak için kullanılır.
* resp: udp ve tcp bağlantısı sonlandırmak amaçlı kullanılır.

<p>Yukarıda verilmiş olan kural seçenekleri, sıklıkla kullanılan kural seçeneklerinin bir kısmıdır. Snort kuralları oluşturulurken yazılmak istenen kurala göre kural seçenekleri değişiklik gösterir bu yüzden faklı seçeneklere ihtiyaç duyabilirsiniz. Bu seçeneklerin daha fazlasına erişmek ve örnek kullanımlarını görmek için. http://manual.snort.org/node27.html bağlantısını kullanabilirsiniz.</p>

## C. Aktif & Dinamik Kurallar

<p>Aktif ve Dinamik kurallar snortun güçlü yönlerinden birisidir. Bu anahtar kelimeler sayesinde çalışan herhangi bir kural başka bir kuralı aktifleştirebilir. 'activate' eylem başlığı kullanan bir aktif kural aynı alarm kuralı gibi davranır, sadece tanımlanırken ek olarak kural seçeneği kısmında 'activates' parametresi  bulunmak zorundadır. Dinamik kural ise 'dynamic' eylem başlığını kullanır ve aynı loglama yapan kurallar gibi davranır. Tanımlanırken kural seçeneği kısmında 'activated_by' parametresi kullanılmak zorundadır.</p>

```activate tcp !$HOME_NET any -> $HOME_NET 143 (flags: PA; content: “|E8C0FFFFFF|/bin”; activates:1; msg: “IMAP buffer overflow!”;)```

``` dynamic tcp !$HOME_NET any -> $HOME_NET 143 (activated_by:1; count:50;)```

> Bu örnekte Snort’a ‘eğer ev ağı dışından bir IP’den 143 numaralı porta paket gelirse ve IMAP taşması olursa sonraki 50 paketi al ve daha sonra analiz etmek için sakla’ komutunu veriyor.
**(Snort Rules - Activate/Dynamic Rules, n.d.)**

## D. Kendi Kurallarımızı Oluşturmak

<p>Snort kuralları oluşturup bu kurallar ile sistemi korumak oldukça kolaydır. Fakat profesyonel seviyede snort kuralları oluşturup saldırı tespit sisteminizi yönetmek için aynı zamanda da TCP/IP, OSI modeli gibi ağ iletişimi, mimarisi ve protokollerini de ileri düzeyde kavramış olmak gerekmektedir.</p>

<p>Basit seviyede snort kuralları yazalım ve bu kuralı sisteme tanıtıp sistemin kuralımıza nasıl cevap verdiğini görelim. Öncelikle kuralımızı yazacağımız kural dosyasını diğer kural dosyalarının olduğu dizine oluşturalım ardından kural başlığı kısmı ile devam edebiliriz.</p>

```# nano /etc/snort/rules/zzz.rules```

1. Kural Başlığı 
      1.  Eylem -> log
      2.  Protokol -> TCP
      3.  Dış ağ -> !IP -> !192.168.2.182
      4.  Kaynak port -> any
      5.  Yön -> '->'
      6.  İç Ağ -> 192.168.2.182
      7. Hedef port -> any

2.  Kural Seçeneği için herhangi bir parametre girmemize bu kural için gerek yok. Aşağıdaki kuralı dosyaya yazdıktan sonra kaydedip çıkabiliriz.

```log TCP !192.168.2.182 any -> 192.168.2.182 any```

<p>Şimdi de kural dosyamızı snort.conf dosyasında yer alan diğer kural dosyalarının arasına ekliyoruz.</p>

```# nano /etc/snort/snort.conf```

 **'include $RULE_PATH/zzz.rules'** satırını ekleyip snort.conf dosyasından çıkıyoruz. Snort’u başlattığımızda 192.168.2.182 adresine, 192.168.2.182 dışındaki tüm IP adreslerinden gelen TCP paketleri kaydeder.

# III. CentOS 6.5’ DE SNORT KURULUMU

Snort kurulumu için gerekli diğer yazılımları indiriyoruz.

``` # yum install libdnet libdnet-devel pcre pcre-devel gcc make flex byacc bison kernel-devel libxml2-devel wget git gcc-c++ zlib zlib-devel libpcap libpcap-devel -y ```

``` # yum update ```

``` # yum upgrade```

Kurulum paketlerinin bulunacağı dizini oluşturup gerekli kurulum paketlerini indirelim.

``` # mkdir -p /usr/local/src/snort/kurulum```

``` # cd /usr/local/src/snort/kurulum```

Eğer gerekli programlar paket deposunda bulunamamış ise aşağıdaki linkler kullanılarak kurulum dosyaları  **‘/usr/local/src/snort/kurulum’** dizinine indirilir. Program zaten paket deposu yardımıyla kurulmuş ise tekrar kurulum dosyasını indirmeye gerek yoktur. 
```
* LIBPCAP : 
	# wget http://www.tcpdump.org/release/libpcap-1.6.1.tar.gz

* LIBDNET : 
	# wget https://libdnet.googlecode.com/files/libdnet-1.12.tgz

* ZLIB : 
	# wget http://prdownloads.sourceforge.net/libpng/zlib-1.2.8.tar.gz

* Snort DAQ:
	# wget https://www.snort.org/downloads/snort/daq-2.0.2.tar.gz

* Snort :
	# wget https://www.snort.org/downloads/snort/snort-2.9.6.2.tar.gz

* Snort Rules:
	# wget https://www.snort.org/downloads/registered/snortrules-snapshot-2962.tar.gz
```

``` # cd ../```

LIBDNET kurulumunu yapmak için:
``` 
# tar -xvzf kurulum/libdnet-1.12.tgz
# cd libdnet-1.12/
#./configure
# make
# make install
# cd /usr/local/lib
# ldconfig –v /usr/local/lib
# cd /usr/local/src/snort/ 
```

LIBPCAP kurulumunu yapmak için:
```
# tar -xvzf kurulum/libpcap-1.6.1.tar.gz
# cd libpcap-1.6.1
# ./configure 
# make 
# make install
# cd /usr/local/lib
# ldconfig –v /usr/local/lib
# cd /usr/local/src/snort/
```

ZLIB kurmak için:
```
# tar -xvzf kurulum/zlib-1.2.8.tar.gz
# cd zlib-1.2.8
# ./configure 
# make 
# make install
# cd /usr/local/lib
# ldconfig –v /usr/local/lib
# cd /usr/local/src/snort/
```
Snort DAQ indirmek ve kurulumunu yapmak için:
```
 *  Otomatik olarak kurulumunu yapmak için aşağıdaki komutu kullanabiliriz:
	# yum install https://www.snort.org/downloads/snort/daq-2.0.2-1.centos6.x86_64.rpm -y 

 *  Tar.gz dosyasından elle kurulum yapmak için 
	# tar -xvzf kurulum/daq-2.0.2.tar.gz
	# cd daq-2.0.2 
	# ./configure 
	# make 
	# make install
	# cd /usr/local/lib
	# ldconfig –v /usr/local/lib
	# cd /usr/local/src/snort/
```

SNORT kurulumunu yapmak için:
```
# tar -xvzf kurulum/snort-2.9.6.2.tar.gz
# cd snort-2.9.6.2/
# ./configure --prefix /usr/local/snort --enable-sourcefire 
# make 
# make install
# cd /usr/local/lib
# ldconfig –v /usr/local/lib
```
Snort Kuralları için: 

Snort kurallarını indirmek için www.snort.org sitesine kayıt olmak gereklidir. Kayıt 
işleminden sonra snort kurallarını indirip sisteme yükleyebiliriz. Bunun için şu komutları 
kullanabiliriz. Aşağıdaki komutu kullanmak işin www.snort.org sitesine **üye girişi yapmalısınız.**

```
# cd /usr/local/src/snort/
# wget https://www.snort.org/downloads/registered/snortrules-snapshot-2962.tar.gz
```
Snort grubu ve kullanıcısı oluşturuyoruz.
```
# groupadd –g 40000 snort
# useradd snort –u 40000 –d /var/log/snort –s /sbin/nologin –c SNORT_IDS –g snort
```
Snort için gerekli dizinleri oluşturup dosya taşıma ve oluşturma işlemlerini yapıyoruz.
```
# mkdir /etc/snort
# mkdir /var/log/snort
# cd /etc/snort
# cp /usr/local/src/snort/snort-2.9.6.2/etc/* .
# tar -xvzf /usr/local/src/snort/kurulum/snortrules-snapshot-2962.tar.gz
# mv /etc/snort/etc/* .
# rm –rf /etc/snort/etc/
# touch /etc/snort/rules/white_list.rules
# touch /etc/snort/rules/black_list.rules
# mkdir /usr/local/lib/snort_dynamicrules
# cp -r /usr/local/snort/lib/snort_dynamicpreprocessor/ /usr/local/lib/
# cp -r /usr/local/snort/lib/snort_dynamicengine /usr/local/lib/
# cd /usr/local/src/snort
```
Gerekli kısayolları oluşturuyoruz.
```
# ln -s /usr/local/snort/bin/snort /usr/sbin/snort
# ln -s /usr/local/snort/bin/snort /usr/bin/snort
```
Snort ile ilgili dosyaların sahibini, yeni oluşturduğumuz snort kişisi olarak ayarlıyoruz ve erişim hakkını da 700 olarak belirliyoruz. Aşağıdaki gibi komutlar kullanarak gerekli dizin ve dosyaların erişim izinlerini düzenliyoruz.
```
# chown –R snort:snort *
# chmod –R 700 *
# chown –R snort:snort /var/log/snort
# chmod –R 700 /var/log/snort
...
# chown -R snort:snort snort_dynamicengine/
# chown -R snort:snort snort_dynamicpreprocessor/
# chmod -R 700 snort_dynamicpreprocessor/
# chmod -R 700 snort_dynamicengine/
# chmod -R 700 /usr/local/lib
# chown -R snort:snort /usr/local/lib
```


Snort yapılandırması için öncelikle snort.conf dosyasını açmalıyız.
```# nano /etc/snort/snort.conf ```
* İlk kısımda bulunan HOME_NET kısmına trafiğini izlemek istediğimiz makinenin IP’sini yazıyoruz bu kısma tek ip yazabileceğimiz gibi bir ip aralığını da yazabiliriz. Bu şu şekilde olur.
```
...
#Setup the network addresses you are protecting

ipvar HOME_NET 192.168.44.132
...
```
```
...
#Setup the network addresses you are protecting

ipvar HOME_NET 192.168.44.1/24
...
```
```
...
#Setup the network addresses you are protecting

ipvar HOME_NET [ !192.168.44.132, 192.168.44.1/24]
...
```
* İç ağımızı belirledikten sonra dış ağı da tanımlayabiliriz bunun için EXTERNAL\_NET kısmında değişiklikler yapılmalıdır. HOME_NET için yazılabilecek tüm şekiller burada da kullanılabilir. Çoğunlukla şu iki şekilde kullanılması tavsiye edilir.
```
...
# Set up the external network addresses. Leave as "any" in most situations

ipvar EXTERNAL_NET !$HOME_NET
...
```
```
...
# Set up the external network addresses. Leave as "any" in most situations

ipvar EXTERNAL_NET any
...
```
* İç ve dış ağ belirlendikten sonra diğer gerekli dosya yollarını doğru bir şekilde yazıyoruz.
__Konfigurasyon dosyasi resmi SEKIL 2__

* Snort çıktılarını istenilen format özelliğine göre uygun biçimde dolduruyoruz. Barnyard2eklentisini kullanacağımız için unified2 formatında kayıt dosyalarına ihtiyacımız olacak bu yüzden çıktı kısmını aşağıdaki gibi düzenliyoruz.
__UNIFIED2 resmi__

* white\_list.rules ve black\_list.rules dosyalarını daha önceden oluşturmuştuk eğer daha önceden bu dosyalar oluşturulmamış ise oluşturulur. Eğer white\_list.rules ve black_list.rules dosyalarınız var ise yazmış olduğunuz daha önceden belirttiğiniz dosya dizinine (/etc/snort/rules) taşıyın.

Yukarıda yapılan düzenlemeler snortun hatasız çalışması için yapılması zorunlu olan kısımlardan oluşmaktadır. Eğer istenirse daha detaylı bir yapılandırma da yapılabilir. Örneğin yapılandırma dosyasında bulunan logdir değişkenine bir dizin atanarak farklı bir kayıt dizini belirlenebilir.

Yapılandırmanın ardından Snort’ u test modunda çalıştırarak Snort’ un eksiksiz bir şekilde kurulup kurulmadığına bakılır. Hatalar veya eksik kütüphaneler var ise bu durumlar düzeltilir. 

```# snort -T –c /etc/snort/snort.conf```

 Snort başarılı bir şekilde kurulmuş ise aşağıdaki gibi bir çıktı elde edilir.
 
 __SEKIL4 HATASIZ SNORT TEST__
 
 Snortun çalışmasını test etmek için aşağıdaki komutları kullanabilirsiniz.

> snort -dev -l /var/log/snort

> snort -l /var/log/snort -b

> snort -dev -r / var/log/snort/snort.log.\_XXX_

Snort kurulumu başarılı bir şekilde tamamlanmış ve yukarıdaki ekran ile karşılaşılmış ise 
artık Snort’ u servis olarak kaydedebiliriz. Bunun için aşağıdaki gerekli işlemleri uyguluyoruz:

Snort kurulum klasörünün içine giriyoruz.
```
# cd /usr/local/src/snort/snort-2.9.6.2
# cp rpm/snortd /etc/init.d/
# chmod +x /etc/init.d/snortd
# cp rpm/snort.sysconfig /etc/sysconfig/snort
# chkconfig --add snortd
```

Kopyaladığımız dosyalarda bazı değişiklikler yapmalıyız. 

* Önce init.d dizinindeki snortd dosyasını yapılandıralım.

```# nano /etc/init.d/snortd ```

Snort barnyard için unified2 modunda kayıt yapmalıdır bu sebebden snortd dosyasındaki snortun çalışmasını sağlayan komutta bazı düzenlemeler yaparak binary kayıt yapmasını engelleyebiliriz.

Şimdi de sysconfig dizinindeki snort dosyasında yapılacak olan değişikleri yapalım.
```
# nano /etc/sysconfig/snort
```
```
...
INTERFACE=eth0
CONF=/etc/snort/snort.conf
USER=snort
GROUP=snort
PASS_FIRST=0
LOGDIR=/var/log/snort
ALERTMODE=fast
DUMP_APP=1
BINARY_LOG=1
NO_PACKET_LOG=0
PRINT_INTERFACE=0
SYSLOG=/var/log/messages
SECS=5
...
```

Snort artık sistemimize servis olarak kaydedildi. Snort’ u kullanmak için artık parametrelere ihtiyacımız kalmadı. Aşağıdaki komutlar ile snortu yönetebiliriz.

> \# service snortd start --> komutu kullanılarak snort başlatılabilir. 

> \# service snortd stop --> komutu ile çalışan snort durdurulabilir.

> \# service snortd restart --> komutu ile snort yeniden başlatılabilir.

> \# service snortd status --> komutu ile snort servisinin durumu hakkında bilgi alınabilir.


# IV. BARNYARD & BASE KURULUMU

Barnyard, Snort’ un çıktılarını kaydettiği dosyadan verileri alıp belirlenmiş olan veri tabanına kaydettiğinden ötürü barnyard kurulumunda önceliği MySQL veri tabanına veriyoruz. 

Bunun için aşağıdaki komutu kullanabiliriz.

MySQL için:
```
#yum install mysql mysql-devel mysql-server php-mysql php-adodb php-pear php-gd httpd libtool git -y
```

## A. Barnyard Kurulumu

Veri tabanını kurduktan sonra Barnyard kurulumuna geçebiliriz. Bunun için önce kurulum dosyalarının bulunduğu dizine gidip Barnyard’i indiriyoruz.
```
# cd /usr/local/src/snort/
# git clone https://github.com/firnsy/barnyard2.git
# cd barnyard2
# autogen.sh –fvi -I ./m4
```

Kurulumun gerçekleşeceği sistem

i386 ise:
```
	# ./configure --with-mysql
```

x86_64 ise:
```
	# ./configure --with-mysql --with-mysql-libraries=/usr/lib64/mysql
```
Komutlarını kullanıyoruz.

```
# make && make install
```

Barnyard yapılandırması ve servis olarak çalışması için:
```
# cp rpm/barnyard2 /etc/init.d/
# chmod +x /etc/init.d/barnyard2
# cp rpm/barnyard2.config /etc/sysconfig/barnyard2
# chkconfig --add barnyard2
```
Barnyard dosyaları için gerekli link ve arşiv klasörünü oluşturuyoruz.
```
# ln -s /usr/local/etc/barnyard2.conf /etc/snort/barnyard.conf
# ln -s /usr/local/bin/barnyard2 /usr/bin/
# mkdir –p /var/log/snort/eth0/archive/
```
Barnyard yapılandırması için:
```
# nano /etc/init.d/barnyard2
```
BARNYARD_OPTS ile başlayan satırdaki -L parametresini -l ile değiştiriyoruz

> ...

> \# chkconfig: 2345 70 60

> ...

> BARNYARD_OPTS="-D -c $CONF -d $SNORTDIR/${INT} -w $WALDO_FILE -l $SNORTDIR/${INT} -a $ARCHIVEDIR -f $LOG_FILE -X $PIDFILE $EXTRA_ARGS"

> ...

```
# chkconfig barnyard2 reset
```
Barnyard’in, sysconfig dizinindeki dosyası içinde bulunan LOG_FILE değişkenini düzenliyoruz.
```
#nano /etc/sysconfig/barnyard2
```
> ...

> LOG_FILE=”snort.log”

> ...



































