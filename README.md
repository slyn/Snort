

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

> output database: log, mysql, user=snort password=test dbname=snort host=localhost

•	SMB pop-up olarak Windows' a göndermek:
> output alert_smb: workstation.list

•	Hem SMB Windows’ a göndermek hem de veri tabanına kayıt etmek:
<p>
Bazen çıktıların birden fazla yere bildirilmesi gerekebilir. Böyle bir durumda ruletype anahtar kelimesiyle eylemimizi belirleyebiliriz. Örneğin snort.conf dosyasında *'smb_db_alert'* olarak belirlediğimiz bir eylem tipi hem veri tabanına kayıt yapıp hem de SMB pop-up uyarısı verecektir. Bunun için aşağıdaki gibi bir bildirim yapılmalıdır.</p>

> ruletype smb_db_alert

>   {

>  	  type alert

>  	  output alert_smb: workstation.list

>  	  output database: log, mysql, user=snort password=test dbname=snort host=localhost

>   }

Bu belirlenen aksiyon tipini snort kurallarında kullanırken de aşağıdaki şekilde kullanılır.
> smb_ddb_alert icmp any any -> 192.168.1.0/24 any (fragbits: D; msg: "Dont Fragment bit set";)

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
