<p align="center">
  <img src="https://raw.githubusercontent.com/Ponywka/MagiTrickle/master/img/logo256.png" alt="MagiTrickle logo"/>
</p>

MagiTrickle
=======


MagiTrickle - Маршрутизация трафика на основе DNS запросов для роутеров Keenetic (под управлением [Entware](https://github.com/The-BB/Entware-Keenetic)).

*(Продукт в данный момент находится в состоянии разработки)*

Данное программное обеспечение реализует маршрутизацию трафика на основе проксирования через себя DNS запросов. Можно указать список доменных имён, которые нужно маршрутизировать на тот, или иной интерфейс, вместо бесконечного накопления IP адресов. 

### Особенности, в сравнении с другим ПО:
1. Не требует отключения встроенного в Keenetic DNS сервера - всё работает методом перенаправления портов.
2. Работает с любыми туннелями, которые умеют поднимать UNIX интерфейс.
3. Несколько типов правил - domain, namespace, wildcard и regex.
4. Не тянет за собой огромное количество сторонних пакетов пакетов. Вся конфигурация находится в одном месте (в одном файле).
5. Возможность создавать несколько групп на разные сети.
6. Моментальное бесшовное включение/выключение сервиса.

### Roadmap:
1. CLI интерфейс для добавления/удаления записей в режиме реального времени. (Уже заложен функционал обработки записей в реальном времени, необходимо заняться CLI интерфейсом)
2. Дружелюбный к пользователю Web-GUI для конфигурации записей.
3. Поддержка подсетей и диапазона IP адресов.
4. Поддержка автообновляемых "подпискок" на список доменных имён (готовые списки подключаемые несколькими кликами мышки). 

### Установка:
Т.к. в данный момент нету никакого дружелюбного к пользователю интерфейсов - данное руководство рассчитано на тех, кому просто нужна маршрутизация на требуемые для него домены без отключения встроенного в Keenetic DNS сервера.

Программа не была досканально протестирована, возможны очень редкие "вылеты". Максимально возможный риск заключается в том, что придётся перезапускать роутер, но шанс этого маловероятен.

1. Устанавливаем пакет:
```bash
opkg install magitrickle_<version>_<arch>.ipk
```
2. Копируем конфиг:
```bash
cp /opt/var/lib/magitrickle/config.yaml.example /opt/var/lib/magitrickle/config.yaml
```
3. Настраиваем конфиг (если не понимаете что делаете - не трогайте группу "app"!):
```yaml
configVersion: 0.1.0
app:                              # Настройки программы - не трогайте, если не знаете что к чему
    dnsProxy:
        host:
            address: '[::]'       # Адрес, который будет слушать программа для приёма DNS запросов
            port: 3553            # Порт
        upstream:
            address: 127.0.0.1    # Адрес, используемый для отправки DNS запросов
            port: 53              # Порт
        disableRemap53: false     # Флаг отключения перепривязки 53 порта
        disableFakePTR: false     # Флаг отключения подделки PTR записи (без неё есть проблемы, может быть будет исправлено в будущем)
        disableDropAAAA: false    # Флаг отключения откидывания AAAA записей
    netfilter:
        iptables:
            chainPrefix: MT_      # Префикс для названий цепочек IPTables
        ipset:
            tablePrefix: mt_      # Префикс для названий таблиц IPSet
            additionalTTL: 3600   # Дополнительный TTL (если от DNS пришел TTL 300, то к этому числу прибавится указанный TTL)
    link:                         # Список адресов где будет подменяться DNS
        - br0
        - br1
    logLevel: info                # Уровень логов (trace, debug, info, warn, error)
groups:                           # Список групп
  - id: d663876a                  # Уникальный ID группы (8 символов в диапозоне "0123456789abcdef")
    name: Routing 1               # Человеко-читаемое имя (для будущего CLI и Web-GUI)
    interface: nwg0               # Интерфейс, на который будет выполняться маршрутизация
    fixProtect: false             # Подключение интерфейса в список для выхода в интернет (для неподдерживаемых Keenetic туннелей)
    rules:                        # Список правил
      - id: 6f34ee91              # Уникальный ID правила (8 символов в диапозоне "0123456789abcdef")
        name: Wildcard Example    # Человеко-читаемое имя (для будущего CLI и Web-GUI)
        type: wildcard            # Тип правила
        rule: '*.example.com'     # Правило
        enable: true              # Флаг активации
      - id: 00ae5f7c
        name: RegEx Example
        type: regex
        rule: '^.*.regex.example.com$'
        enable: true
  - id: d663876b
    name: Routing 2
    interface: nwg1
    fixProtect: false
    rules:
      - id: 6120dc8a
        name: Domain Example
        type: domain
        rule: 'domain.example.com'
        enable: true
```
Примеры правил:
* Domain (один домен без поддоменов)
```yaml
      - id: 6120dc8a
        name: Domain Example
        type: domain
        rule: 'example.com'
        enable: true
```
* Namespace (домен и все его поддомены)
```yaml
      - id: b9751782
        name: Namespace Example
        type: namespace
        rule: 'example.com'
        enable: true
```
* Wildcard
```yaml
      - id: 6f34ee91
        name: Wildcard Example
        type: wildcard
        rule: '*.example.com'
        enable: true
```
* RegEx
```yaml
      - id: 00ae5f7c
        name: RegEx Example
        type: regex
        rule: '^.*.regex.example.com$'
        enable: true
```
4. Запускаем сервис:
```bash
/opt/etc/init.d/S99magitrickle start
```

### Отладка
Если вам нужна отладка, то останавливаем сервис и запускаем "демона" руками:
```bash
/opt/etc/init.d/S99magitrickle stop
magitrickled
```
