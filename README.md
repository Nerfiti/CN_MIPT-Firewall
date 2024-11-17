# Простейший межсетевой экран, основанный на перенаправлении всего трафика в python скрипт через nfqueue

Рабочая конфигурация
---
Для тестов была собрана следующая конфигурация:
![image](https://github.com/user-attachments/assets/0ff06535-8cb2-487f-bc37-bb5b20f22cd9)

Компьютер посередине выступает в роли межсетевого экрана. На нём настроена пересылка пакетов через `nfqueue` через утилиту `iptables`.

Тесты
---
Для тестирования были составлены следующие правила:
![image](https://github.com/user-attachments/assets/4e0952c9-51d2-4ad0-8ccc-256529f27e26)

Для проверки корректной фильтрации посылались `http` запросы, которые можно увидеть на картинке в левом терминале. Правый терминал принадлежит МСЭ. В нём можно увидеть результат работы программы.
![image](https://github.com/user-attachments/assets/d50346f3-1847-420f-8918-fe4827233e58)
