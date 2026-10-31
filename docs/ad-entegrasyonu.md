# Active Directory Entegrasyonu

Kullanıcılar AD hesaplarıyla **LDAPS** üzerinden giriş yapar. Rol ve OU kapsamı AD gruplarından belirlenir. Şifresiz LDAP (389) desteklenmez.

## Kurulum

1. AD'de salt okuma yetkili bir **hizmet hesabı** oluşturun (ör. `CN=svc-ber,OU=Hizmet Hesapları,DC=corp,DC=example`). Kullanıcı ve grup nesnelerini okuyabilmesi yeterlidir.
2. BerOps için gruplar oluşturun:

   | Grup | Rol | Kapsam |
   |---|---|---|
   | `BerOps-Admins` | Admin | — |
   | `BerOps-Teknisyen` | Teknisyen | — |
   | `BerOps-Izmir-Teknik` | Teknisyen | `OU=İzmir,OU=Şubeler,…` |
   | `BerOps-Izleyici` | Salt Okunur | — |

3. Konsolda **Ayarlar → Active Directory**:
   - **Sunucu adresi:** `ldaps://dc01.corp.example` (port varsayılan 636).
   - **Arama temel DN'i:** `DC=corp,DC=example`.
   - **Hizmet hesabı DN'i ve parolası.** Parola sunucuda AES-256-GCM ile şifrelenir (`data_dir/pki/secret.key`) ve konsolda bir daha gösterilmez.
   - **İç CA sertifikası:** etki alanı denetleyicisinin sertifikası kurumsal CA'dan veriliyorsa CA sertifikasını PEM olarak yapıştırın.
4. **Bağlantıyı test et** ile hizmet hesabını, **Kullanıcıyla test et** ile bir kullanıcının girişini, gruplarını ve eşlenecek rolünü (oturum açmadan) doğrulayın.
5. **Grup → rol eşlemelerini** ekleyin ve **AD ile girişi etkinleştirin**.

## Giriş akışı

1. Kullanıcı adı `ayse`, `CORP\ayse` veya `ayse@corp.example` biçiminde girilebilir.
2. Aynı adda **yerel** bir hesap varsa yerel parola kullanılır; yerel hesaplar AD girişiyle ele geçirilemez.
3. Hizmet hesabıyla kullanıcı aranır (`sAMAccountName` veya `userPrincipalName`) ve kullanıcının **kendi parolasıyla** bağlanılarak doğrulanır. Boş parola reddedilir.
4. **İç içe grup üyelikleri** AD'nin `LDAP_MATCHING_RULE_IN_CHAIN` kuralıyla bulunur.
5. Kullanıcı birden fazla eşlenmiş gruptaysa **en yetkili rol** seçilir. Aynı roldeki eşlemelerin kapsamları birleştirilir; biri kapsamsızsa kullanıcı kapsamsızdır.
6. Hiçbir eşleme uymazsa giriş reddedilir ve denetim kaydına "AD grubu hiçbir role eşlenmiyor" yazılır.
7. AD'de devre dışı (`userAccountControl`) hesaplar giriş yapamaz. Konsoldan devre dışı bırakılan AD kullanıcısı da giremez.

Rol ve kapsam **her girişte** yeniden hesaplanır; gruptan çıkarılan kullanıcı sonraki girişinde yetkisini kaybeder. Açık oturumlar en fazla oturum süresi kadar (varsayılan 30 dk boşta, 12 saat mutlak) geçerli kalır.

## AD erişilemezse

AD'ye ulaşılamıyorsa AD kullanıcıları giriş yapamaz ve konsol **kurtarma hesabı** kullanılmasını önerir. Kurulumda en az bir yerel admin hesabı oluşturun ve güvenli saklayın:

```bash
berops-server admin create -username kurtarma -recovery
```

## AD bilgisayarları

AD etkinse **Ayarlar → Active Directory → AD bilgisayarları** ekranı, AD'deki bilgisayar nesnelerini listeler ve ajanı kurulu olmayanları gösterir. Eşleştirme bilgisayar adı ve DNS adının ilk parçasıyla yapılır. Liste saklanmaz; her açılışta AD'den okunur. Kapsamlı kullanıcılar yalnızca kapsamlarındaki bilgisayarları görür.
