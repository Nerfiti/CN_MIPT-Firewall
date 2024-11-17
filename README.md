# Простейшая реализация межсетевого экрана с ипользованием механизма сырых сокетов.

Рабочая конфигурация
---
Для тестирования был создан виртуальный стенд. Компьютеры в сети расположены следующим образом:
![image](https://github.com/user-attachments/assets/86dff765-ccc7-4d33-9268-9a868717e58f)
Компьютер по центру выступает в роли межсетевого экрана. На нём есть файл с правилами и запущенная программа, которая читает из одного сокета, проводит необходимые проверки и, если пакету "разрешено" идти дальше, то перенаправляет его в другой сокет.

Тесты
---
Для тестирования были созданы несколько правил (можно увидеть на скриншоте в правой консоли), а также отправлены несколько пакетов:
- TCP пакет (в левой консоли немного непонятно, что происходит, поэтому в принципе достаточно смотреть только на правую), который был отклонён
- UDP пакет, который был пропущен дальше в сеть по правилу (proto=UDP)
- ICMP пакет (ping), который был пропущен по правилу (src/dst_ip=8.8.8.8)
![image](https://github.com/user-attachments/assets/538ff9ca-3445-49b7-b45f-0b31b7fa1977)

