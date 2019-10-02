# How to demo iptables on Centos 

- ## Pull The Centos Image from Docker Hub
         This command will search for a local image and if one does not exist it will pull remotely from docker hub.
    > `docker pull chellong7798/iptablesdocument` <br/>
    > `docker run --cap-add=NET_ADMIN -p 22 --rm -ti --name u2 --network test chellong7798/iptablesdocument bash`
    > `cat /etc/os-release` (show os-release)


- ## List Container Activity
        Confirm we have run our Centos container.
    > `docker ps -a`

- ## Access our Running Centos Container
        Log into our container as root.
    > `docker exec -it _container_id_ bash`

- ## Make a Change - Create a Directory
        Just to prove that we can make changes within this container and that those changes will persist throughout this process.
    > `mkdir iptablesDocument`

- ## Logout of the Container
    >`exit`


- ## List Container Activity
    >`docker ps -a`


- ## List Docker Images
    >`docker images`

- ## Create a Repository in Docker Hub
        Navigate the UI on Docker Hub to create a public repository which we will push to.

- ## Stop the Docker Container
   > `docker stop _container_id_`

-  ## Commit Our Container Changes to the Local Centos Image
    > `docker commit _container_id_  _username_/tutorials`

-  ## Push the Image to Docker Hub
    > `docker push _username_/tutorials`


<h1>How To Set Up a Basic Iptables Firewall on Centos</h1>

**Preface** <br>
    *Chúng ta đang sống trong thời đại của cuộc cách mạng Internet kết nối toàn cầu. Mạng Internet đã mở ra những cơ hội vô cùng to lớn cho con người trong công cuộc hành trình tìm kiếm tri thức, nhưng đồng thời cũng phát sinh một vấn đề quan trọng hơn đó là đảm bảo sự an toàn của người sử dụng trên không gian mạng công khai đó. Trong vài năm trở lại đây xu hướng tấn công có chủ đích (APT) đang diễn biến hết sức phức tạp trên diện rộng. Đây là hình thức tấn công tinh vi và rất khó phát hiện do kẻ tấn công sử dụng các kỹ thuật mới để ẩn nấp và những cuộc tấn công này nhằm vào những người dùng hay các hệ thống quan trọng nhằm đánh cắp thông tin, phá hoại hệ thống và có thể xem là mối rủi ro nguy hiểm thường trực hiện nay trên Internet không chỉ ở Việt Nam và trên thế giới. Không nằm ngoài xu thế đó thì đây vẫn là xu hướng chính và cần tiếp tục được quan tâm và chú trọng trong năm 2019.*

*Giúp người đọc phần nào hình dung được nguyên lý hoạt động của một chương trình Firewall điển hình, cùng với những phương thức tấn công căn bản và cách ngăn chặn chúng. Người dùng có thể tự cài đặt Firewall này vào hệ thống Web-server của mình, từ đó phát triển lên một hệ thống tốt hơn và qui mô hơn.*

## **Introdution** <br>
**iptables là gì.** <br>
iptables là một tường lửa ứng dụng lọc gói dữ liệu rất mạnh, miễn phí và có sẵn trên Linux. iptables cho phép người quản trị Linux cấu hình cho phép/chặn luồng dữ liệu đi qua mạng. iptables có thể đọc, thay đổi, chuyển hướng hoặc hủy các gói tin đi tới/đi ra dựa trên các tables, chains và rules. Mỗi một table sẽ có nhiều chain chứa các rule khác nhau quyết định cách thức xử lý gói tin (dựa trên giao thức, địa chỉ nguồn, đích….).

iptables nằm ngoài nhân. iptables chịu trách nhiệm giao tiếp giữa người dùng và Netfilter để đẩy các luật của người dùng vào cho Netfiler xử lí. Netfilter tiến hành lọc các gói dữ liệu ở mức IP. Netfilter làm việc trực tiếp trong nhân, nhanh và không làm giảm tốc độ của hệ thống.

Để đi sâu vào cách thức hoạt động của iptables, ta cần phải hiểu rõ về các khái niệm như table, chain và rule được mô tả bên dưới.

2. ## install iptables
    IPTABLES được cài mặc định trong hệ thống Linux. Package của iptables là iptables-version.rpm hoặc iptables-version.tgz

    Lệnh cài đặt (trên Centos): `$ apt-get install iptables`

    Lệnh cài đặt (trên Redhat/CentOS): `$ yum install iptables`

3. ## Start iptables 
        Câu lệnh start, stop, và restart iptables.
    > **[root@4e12c789765f iptablesDocument]#** `service iptables start` <br/>

    > **[root@4e12c789765f iptablesDocument]#** `service iptables stop` <br/>

    > **[root@4e12c789765f iptablesDocument]#** `service iptables restart` <br/>

        Để khởi động iptables mỗi khi khởi động máy.
    > **[root@4e12c789765f iptablesDocument]#** `chkconfig iptables on` <br/>

        Để xem tình trạng của iptables
    > **[root@4e12c789765f iptablesDocument]#** `service iptables status` <br/>

4. ## Tables in iptables
   - ### **Filter table** <br>
   *Filter là bảng được dùng nhiều nhất trong iptables. Bảng này dùng để quyết định xem có nên cho một gói tin tiếp tục đi tới đích hoặc chặn gói tin này lại (lọc gói tin). Đây là chức năng chính yếu nhất của iptables, nếu các lệnh không khai báo bảng đích thì mặc định sẽ là bảng Filter.*

   - ### **NAT (Network Address Translation) table** <br>
    *Bảng NAT được dùng để phiên dịch địa chỉ mạng, khi các gói tin đi vào bảng này, gói tin sẽ được kiểm tra xem có cần thay đổi và sẽ thay đổi địa chỉ nguồn, đích của gói tin như thế nào.* <br>
    *Bảng này được sử dụng khi có một gói tin từ một connection mới gởi đến hệ thống, các gói tin tiếp theo của connection này sẽ được áp rule và xử lý tương tự như gói tin đầu tiên mà không cần phải đi qua bảng NAT nữa.* <br>
    ![alt](https://cloudcraft.info/wp-content/uploads/2017/11/gioi-thieu-ve-iptables-1.png) <br>
    <center><i>Sơ đồ xử lý gói tin cơ bản qua 2 bảng NAT và FILTER</i></center>
    
   -  **Mangle Table** 
  
    *Bảng mangle dùng để điều chỉnh một số trường trong IP header như TTL (Time to Live), TOS (Type of Serivce) dùng để quản lý chât lượng dịch vụ (Quality of Serivce)… hoặc dùng để đánh dấu các gói tin để xử lý thêm trong các bảng khác.*
   - ### **Raw Table** <br>
    *Theo mặc định, iptables sẽ lưu lại trạng thái kết nối của các gói tin, tính năng này cho phép iptables xem các gói tin rời rạc là một kết nối, một session chung để dễ dàng quản lý. Tính năng theo dõi này được sử dụng ngay từ khi gói tin được gởi tới hệ thống trong bảng raw.*
    *Với bảng raw, ta có thể bật/tắt tính năng theo dõi này đối với một số gói tin nhất định, các gói tin được đánh dấu NOTRACK sẽ không được ghi lại trong bảng connection tracking nữa.*
   - ### **Security Table** <br>
    *Bảng security dùng để đánh dấu policy của SELinux lên các gói tin, các dấu này sẽ ảnh hưởng đến cách thức xử lý của SELinux hoặc của các máy khác trong hệ thống có áp dụng SELinux. Bảng này có thể đánh dấu theo từng gói tin hoặc theo từng kết nối.*

5. ## Các tham số dòng lệnh thường gặp của Iptables
   1. ### Gọi trợ giúp
   Để gọi trợ giúp về Iptables, bạn gõ lệnh $ man iptables hoặc $ iptables –help. Chẳng hạn nếu bạn cần biết về các tùy chọn của match limit, bạn gõ lệnh $ iptables -m limit –help.
   1. Các tùy chọn để chỉ định thông số
      - chỉ định tên table: -t , ví dụ -t filter, -t nat, .. nếu không chỉ định table, giá trị mặc định là filter
      - chỉ đinh loại giao thức: -p , ví dụ -p tcp, -p udp hoặc -p ! udp để chỉ định các giao thức không phải là udp
      - chỉ định card mạng vào: -i , ví dụ: -i eth0, -i lo
      - chỉ định card mạng ra: -o , ví dụ: -o eth0, -o pp0
      - chỉ định địa chỉ IP nguồn: -s <địa_chỉ_ip_nguồn>, ví dụ: -s 192.168.0.0/24 (mạng 192.168.0 với 24 bít mạng), -s 192.168.0.1-192.168.0.3 (các IP 192.168.0.1, 192.168.0.2, 192.168.0.3).
      - chỉ định địa chỉ IP đích: -d <địa_chỉ_ip_đích>, tương tự như -s
      - chỉ định cổng nguồn: –sport , ví dụ: –sport 21 (cổng 21), –sport 22:88 (các cổng 22 .. 88), –sport :80 (các cổng <=80), –sport 22: (các cổng >=22)
      - chỉ định cổng đích: –dport , tương tự như –sport
   2. ### Các tùy chọn để thao tác với chain
      - tạo chain mới: `iptables -N`
      - xóa hết các luật đã tạo trong chain: `iptables -X`
      - đặt chính sách cho các chain `built-in` (INPUT, OUTPUT & FORWARD): `iptables -P` , ví dụ: `iptables -P INPUT ACCEPT `để chấp nhận các packet vào chain INPUT
      - liệt kê các luật có trong chain: `iptables -L`
      - xóa các luật có trong chain (flush chain): `iptables -F`
      - reset bộ đếm packet về 0: `iptables -Z`
      1. Các tùy chọn để thao tác với luật
      - thêm luật: `-A` (append)
      - xóa luật: `-D` (delete)
      - thay thế luật: `-R` (replace)
      - chèn thêm luật: `-I` (insert)
      Phân biệt giữa ACCEPT, DROP và REJECT packet
      - **ACCEPT**: chấp nhận packet
      - **DROP**: thả packet (không hồi âm cho client)
      - **REJECT**: loại bỏ packet (hồi âm cho client bằng một packet khác)
   ## Ví dụ:
   `iptables -A INPUT -i eth0 –dport 80 -j ACCEPT` chấp nhận các packet vào cổng 80 trên card mạng eth0
   `iptables -A INPUT -i eth0 -p tcp –dport 23 -j DROP` thả các packet đến cổng 23 dùng giao thức TCP trên card mạng eth0
   `iptables -A INPUT -i eth1 -s ! 10.0.0.1-10.0.0.5 –dport 22 -j REJECT –reject-with tcp-reset` gởi gói TCP với cờ RST=1 cho các kết nối không đến từ dãy địa chỉ IP 10.0.0.1..5 trên cổng 22, card mạng eth1
   `iptables -A INPUT -p udp –dport 139 -j REJECT –reject-with icmp-port-unreachable` gởi gói ICMP `port-unreachable` cho các kết nối đến cổng 139, dùng giao thức UDP​
   Phân biệt giữa NEW, ESTABLISHED và RELATED
      - NEW: mở kết nối mới
      - ESTABLISHED: đã thiết lập kết nối
      - RELATED: mở một kết nối mới trong kết nối hiện tại​
   ## Ví dụ:
   `iptables -P INPUT DROP` đặt chính sách cho chain INPUT là DROP <br>
   `iptables -A INPUT -p tcp –syn -m state –state NEW -j ACCEPT` chỉ chấp nhận các gói TCP mở kết nối đã set cờ SYN=1 <br>
   `iptables -A INPUT -m state –state ESTABLISHED,RELATED -j ACCEPT` không đóng các kết nối đang được thiết lập, đồng thời cũng cho phép mở các kết nối mới trong kết nối được thiết lập <br>
   `iptables -A INPUT -p tcp -j DROP` các gói TCP còn lại đều bị DROP​. <br>
   Tùy chọn –limit, –limit-burst <br>
   - limit-burst: mức đỉnh, tính bằng số packet
   - limit: tốc độ khi chạm mức đỉnh, tính bằng số packet/s(giây), m(phút), d(giờ) hoặc h(ngày)​
   
   Mình lấy ví dụ cụ thể để bạn dễ hiểu: <br>
   `iptables -N test`
   `iptables -A test -m limit –limit-burst 5 –limit 2/m -j RETURN`
   `iptables -A test -j DROP`
   `iptables -A INPUT -i lo -p icmp –icmp-type echo-request -j test​` <br>
   Đầu tiên lệnh iptables -N test để tạo một chain mới tên là test (table mặc định là filter). Tùy chọn -A test (append) để thêm luật mới vào chain test. Đối với chain test, mình giới hạn limit-burst ở mức 5 gói, limit là 2 gói/phút, nếu thỏa luật sẽ trở về (RETURN) còn không sẽ bị DROP. Sau đó mình nối thêm chain test vào chain INPUT với tùy chọn card mạng vào là lo, giao thức icmp, loại icmp là echo-request. Luật này sẽ giới hạn các gói PING tới lo là 2 gói/phút sau khi đã đạt tới 5 gói. <br>
   Bạn thử ping đến localhost xem sao? <br>
   $ `ping -c 10 localhost​` <br>
   Chỉ 5 gói đầu trong phút đầu tiên được chấp nhận, thỏa luật RETURN đó. Bây giờ đã đạt đến mức đỉnh là 5 gói, lập tức Iptables sẽ giới hạn PING tới lo là 2 gói trên mỗi phút bất chấp có bao nhiêu gói được PING tới lo đi nữa. Nếu trong phút tới không có gói nào PING tới, Iptables sẽ giảm limit đi 2 gói tức là tốc độ đang là 2 gói/phút sẽ tăng lên 4 gói/phút. Nếu trong phút nữa không có gói đến, limit sẽ giảm đi 2 nữa là trở về lại trạng thái cũ chưa đạt đến mức đỉnh 5 gói. Quá trình cứ tiếp tục như vậy. Bạn chỉ cần nhớ đơn giản là khi đã đạt tới mức đỉnh, tốc độ sẽ bị giới hạn bởi tham số–limit. Nếu trong một đơn vị thời gian tới không có gói đến, tốc độ sẽ tăng lên đúng bằng –limit đến khi trở lại trạng thái chưa đạt mức –limit-burst thì thôi. <br>
   Để xem các luật trong Iptables bạn gõ lệnh $ iptables -L -nv (-L tất cả các luật trong tất cả các chain, table mặc định là filter, -n liệt kê ở dạng số, v để xem chi tiết) <br>
   `iptables -L -nv` <br>
   Chain INPUT (policy ACCEPT 10 packets, 840 bytes)
   pkts bytes target prot opt in out source destination
   10 840 test icmp — lo * 0.0.0.0/0 0.0.0.0/0 icmp type 8
   Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
   pkts bytes target prot opt in out source destination
   Chain OUTPUT (policy ACCEPT 15 packets, 1260 bytes)
   pkts bytes target prot opt in out source destination
   Chain test (1 references)
   pkts bytes target prot opt in out source destination
   5 420 RETURN all — * * 0.0.0.0/0 0.0.0.0/0 limit: avg 2/min burst 5
   5 420 DROP all — * * 0.0.0.0/0 0.0.0.0/0
   - `iptables -Z` reset counter
   - `iptables -F` flush luật
   - `iptables -X` xóa chain đã tạo​

6. ## Các chain trong table
        Mỗi một table đều có một số chain của riêng mình, sau đây là bảng cho biết các chain thuộc mỗi table
![alt](https://i.gyazo.com/237ad8b16f5ade86dcc7cb1876184c63.png) <br>
<center><i>Các chain có trong từng table</i></center>

Giới thiệu về các chain:
- **INPUT**: – Chain này dùng để kiểm soát hành vi của những các kết nối tới máy chủ. Ví dụ một user cần kết nối SSH và máy chủ, iptables sẽ xét xem IP và port của user này có phù hợp với một rule trong chain INPUT hay ko. 
- **FORWARD**: – Chain này được dùng cho các kết nối chuyển tiếp sang một máy chủ khác (tương tự như router, thông tin gởi tới router sẽ được forward đi nơi khác). Ta chỉ cần định tuyến hoặc NAT một vài kết nối (cần phải forward dữ liệu) thì ta mới cần tới chain này.
- **OUTPUT**: – Chain này sẽ xử lý các kết nối đi ra ngoài. Ví dụ như khi ta truy cập google.com, chain này sẽ kiểm tra xem có rules nào liên quan tới http, https và google.com hay không trước khi quyết định cho phép hoặc chặn kết nối.
- **PREROUTING**: – Header của gói tin sẽ được chỉnh sửa tại đây trước khi việc routing được diễn ra.
- **POSTROUTING**: – Header của gói tin sẽ được chỉnh sửa tại đây trước khi việc routing được diễn ra.
Mặc định thì các chain này sẽ không chứa bất kỳ một rule nào, tuy nhiên mỗi chain đều có một policy mặc định nằm ở cuối chain, policy này có thể là **ACCEPT** hoặc **DROP**, chỉ khi gói tin đã đi qua hết tất cả các rule ở trên thì gói tin mới gặp phải policy này.
Ngoài ra, thứ tự gói tin di chuyển giữa các chain sẽ có hơi khác tùy vào tình huống:

- Gói tin được gởi đến máy chủ: **PREROUTING** => **INPUT**
- Gói tin được forward đến một máy chủ khác: **PREROUTING** => **FORWARD** => **POSTROUTING**
- Gói tin được máy chủ hiện tại gởi ra ngoài: **OUTPUT** => **POSTROUTING** <br>
  ![alt](https://cloudcraft.info/wp-content/uploads/2017/11/gioi-thieu-ve-iptables-2.png.jpg) <br>
6. ## Các rule trong chain
*Các rule là tập điều kiện và hành động tương ứng để xử lý gói tin (ví dụ ta sẽ tạo một rule chặn giao thức FTP, drop toàn bộ các gói tin FTP được gởi đến máy chủ). Mỗi chain sẽ chứa rất nhiều rule, gói tin được xử lý trong một chain sẽ được so với lần lượt từng rule trong chain này.* <br>
*Cơ chế kiểm tra gói tin dựa trên rule vô cùng linh hoạt và có thể dễ dàng mở rộng thêm nhờ các extension của IPtables có sẵn trên hệ thống. Rule có thể dựa trên protocol, địa chỉ nguồn/đích, port nguồn/đích, card mạng, header gói tin, trạng thái kết nối… Dựa trên những điều kiện này, ta có thể tạo ra một tập rule phức tạp để kiểm soát luồng dữ liệu ra vào hệ thống.*
*Mỗi rule sẽ đươc gắn một hành động để xử lý gói tin, hành động này có thể là:*
- **ACCEPT**: gói tin sẽ được chuyển tiếp sang bảng kế tiếp.
- **DROP**: gói tin/kết nối sẽ bị hủy, hệ thống sẽ không thực thi bất kỳ lệnh nào khác.
- **REJECT**: gói tin sẽ bị hủy, hệ thống sẽ gởi lại 1 gói tin báo lỗi ICMP – Destination port unreachable
- **LOG**: gói tin khớp với rule sẽ được ghi log lại.
- **REDIRECT**: chuyển hướng gói tin sang một proxy khác.
- **MIRROR**: hoán đổi địa chỉ IP nguồn, đích của gói tin trước khi gởi gói tin này đi.
- **QUEUE**: chuyển gói tin tới chương trình của người dùng qua một module của kernel.
7. ## Các trạng thái của kết nối
   *Đây là những trạng thái mà hệ thống connection tracking (module conntrack của IPtables) theo dõi trạng thái của các kết nối:*
- **NEW**: Khi có một gói tin mới được gởi tới và không nằm trong bất kỳ connection nào hiện có, hệ thống sẽ khởi tạo một kết nối mới và gắn nhãn NEW cho kết nối này. Nhãn này dùng cho cả TCP và UDP.
- **ESTABLISHED**: Kết nối được chuyển từ trạng thái NEW sang ESTABLISHED khi máy chủ nhận được phản hồi từ bên kia.
- **RELATED**: Gói tin được gởi tới không thuộc về một kết nối hiện có nhưng có liên quan đến một kết nối đang có trên hệ thống. Đây có thể là một kết nối phụ hỗ trợ cho kết nối chính, ví dụ như giao thức FTP có kết nối chính dùng để chuyển lệnh và kết nối phụ dùng để truyền dữ liệu.
- **INVALID**: Gói tin được đánh dấu INVALID khi gói tin này không có bất cứ quan hệ gì với các kết nối đang có sẵn, không thích hợp để khởi tạo một kết nối mới hoặc đơn giản là không thể xác định được gói tin này, không tìm được kết quả trong bảng định tuyến.
- **UNTRACKED**: Gói tin có thể được gắn hãn UNTRACKED nếu gói tin này đi qua bảng raw và được xác định là không cần theo dõi gói này trong bảng connection tracking.
- **SNAT**: Trạng thái này được gán cho các gói tin mà địa chỉ nguồn đã bị NAT, được dùng bởi hệ thống connection tracking để biết khi nào cần thay đổi lại địa chỉ cho các gói tin trả về.
- **DNAT**: Trạng thái này được gán cho các gói tin mà địa chỉ đích đã bị NAT, được dùng bởi hệ thống connection tracking để biết khi nào cần thay đổi lại địa chỉ cho các gói tin gởi đi.
*Các trạng thái này giúp người quản trị tạo ra những rule cụ thể và an toàn hơn cho hệ thống.*
8. ## Cấu hình IPtables cơ bản
*Các lệnh cơ bản của iptables*
![alt](https://i.gyazo.com/c2dd3460e99701e8e38250f7e43fbfaa.png)<br>
*Các cờ cấu hình rule cho iptables*
![alt](https://i.gyazo.com/305bc0747b1b135b7f93cbcd86566f14.png)<br>
*Sau đây là một mẫu cấu hình iptables cơ bản cho các bạn tham khảo:*
```bash
###  Allow INBOUND connections ###
 
## Rules are evaluated in order, put busiet rules at the front!! ##
## Accept all traffic to the looback interface, ##
## which is necessary for many applications and services ##
iptables -A INPUT -i lo -j ACCEPT
 
### Stateful table ###
## Allow traffic from existing connections or new connection related to these connections ##
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
 
## Block invalid packets ##
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
 
## Allow inbound port 22, 80, 443 ##
iptables -A INPUT -i <input_interface> -d <server_IP> -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -i <input_interface> -d <server_IP> -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -i <input_interface> -d <server_IP> -p tcp --dport 22 -j ACCEPT
 
## Block dropped packets ##
#iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: "
 
## Allow DNS server (UDP/TCP) return result ##
## If use stateless table, enable the two below ##
#iptables -A INPUT -i <input_interface> -p tcp --sport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#iptables -A INPUT -i <input_interface> -p udp --sport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
 
## Allow NTP Server return result ##
iptables -A INPUT -p udp --sport 123 -j ACCEPT
 
## Except the listed above, other connections will be dropped ##
iptables -t filter -P INPUT DROP
--------------------------------------
 
###  Allow OUTBOUND connections ###
## Accept all traffic to the looback interface, ##
## which is necessary for many applications and services ##
iptables -A OUTPUT -o lo -j ACCEPT
 
## Allow Established outgoing connections ##
iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
 
## Allow outbound SSH, Web Traffic ##
iptables -A OUTPUT -o <output_interface> -p tcp --sport 80 -j ACCEPT
iptables -A OUTPUT -o <output_interface> -p tcp --sport 443 -j ACCEPT
iptables -A OUTPUT -o <output_interface> -p tcp --sport 22 -j ACCEPT
 
## Allow HTTP/HTTPS traffic to other server (yum install) ##
iptables -A OUTPUT -o <output_interface> -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -o <output_interface> -p tcp --dport 443 -j ACCEPT
 
## Allow DNS (TCP/UDP port 53), NTP (port 123) ##
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
 
## Block dropped packets ##
#iptables -A OUTPUT -j LOG --log-prefix "IPTables-Dropped: "
 
## Except the listed above, other connections will be dropped ##
iptables -t filter -P OUTPUT DROP

```

9. ## Tham khảo
Dataflow hoàn chỉnh của IPtables: 
[Wikipedia](https://upload.wikimedia.org/wikipedia/commons/3/37/Netfilter-packet-flow.svg)

[http://ipset.netfilter.org/iptables.man.html](http://ipset.netfilter.org/iptables.man.html)
[https://wiki.archlinux.org/index.php/iptables](https://wiki.archlinux.org/index.php/iptables)
[https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture](https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture)
[https://wiki.archlinux.org/index.php/Simple_stateful_firewall](https://wiki.archlinux.org/index.php/Simple_stateful_firewall)


10. ## Demo 
- `iptables -h` 
  
- ## giới thiệu qua về quy tắc tường lửa 
  - Mặc định thì iptables sẽ không có bất cứ quy tắc nào cả.
  - `iptables -L --line-numbers`
  > Cột pkts hoặc gói cho biết có bao nhiêu gói đã đi qua chuỗi, trong khi cột byte cho thấy tổng số byte đã đi qua nó. <br>
    **TARGET**: Hành động sẽ thực thi cho mỗi chuỗi quy tắc. <br>
    **PROT**: Là viết tắt của chữ Protocol, nghĩa là giao thức. Tức là các giao thức sẽ được áp dụng để thực thi quy tắc này. Ở đây chúng ta có 3 lựa chọn là all, tcp hoặc udp. Các ứng dụng như SSH, FTP, sFTP,..đều sử dụng giao thức kiểu TCP. <br>
    **IN**: Thiết bị mạng nhận kết nối vào được áp dụng cho quy tắc, chẳng hạn như lo, eth0, eth1. <br>
    **OUT**: Thiết bị mạng phục vụ nhu cầu gửi kết nối ra ngoài được áp dụng quy tắc. <br>
    **DESTINATION**: Địa chỉ của lượt truy cập được phép áp dụng quy tắc.<br>
- ## demo input chain iptables
  1. **ubuntu:** `ping 172.17.0.2`
  2. **centos:** `iptables -P INPUT DROP` (chặn tất cả các kết nối từ bên ngoài)
  3. **ubuntu:**: `ping 172.17.0.2` (không ping được)
   
- ## demo input chain reject rule
  1. **ubuntu:** `ping 172.17.0.2`
  2. **centos:** `iptables -A INPUT -s 172.17.0.2 -j REJECT`
  3. **ubuntu:** `ping 172.17.0.2` (access denied)

- ## demo 1 số quy tắc 
  1. `iptables -A INPUT -i lo -j ACCEPT`
        -A INPUT: khai báo kiểu kết nối sẽ được áp dụng (A nghĩa là Append).
        -i lo: Khai báo thiết bị mạng được áp dụng (i nghĩa là Interface).
        -j ACCEPT: khai báo hành động sẽ được áp dụng cho quy tắc này (j nghĩa là Jump).
  2. `iptables -A INPUT -p tcp --dport 22 -j ACCEPT` (quy tắc cho phép truy cập cổng 22 của SSH.)
        -p tcp: Giao thức được áp dụng.
        –dport 22: Cổng cho phép áp dụng.
  3. `iptables -A INPUT -p tcp --dport 80 -j ACCEPT` (cho phép truy cập cổng 80) 
  4. `iptables -A INPUT -j DROP` (khóa toàn bộ các kết nối còn lại:)
  5. `iptables -L --line-numbers`
  6. Ở phần tạo quy tắc, bạn có để ý là chúng ta luôn sử dụng tham số -A (tức là Append) để nối một quy tắc mới vào danh sách các quy tắc của iptables, mỗi khi tạo mới một quy tắc nó sẽ tự động đưa vào cuối cùng.
Nhưng nếu bạn muốn thêm một quy tắc và đặt nó vào vị trí như mong muốn thì sẽ sử dụng tham số -I thay cho -A, chẳng hạn như:
    `iptables -I INPUT 2 -p tcp --dport 443 -j ACCEPT`
    Trong đó, -I INPUT 2 nghĩa là mình đặt quy tắc này vào dòng thứ 2 trong danh sách các quy tắc thuộc loại kết nối INPUT. Cũng xin nói thêm là cổng 443 chính là cổng HTTPS/SSL.
- ## demo delete change in iptables
  1. `iptables -L --line-numbers`
  2. `iptables -F INPUT` (delete all chain)
  3. `iptables -D INPUT ${index}` (delete by index)

