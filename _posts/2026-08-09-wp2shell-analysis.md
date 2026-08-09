---
layout: post
title: "wp2shell: Khi hai lỗi WordPress ghép lại thành RCE không cần đăng nhập"
date: 2026-08-09 09:00:00 +0700
categories: [Security, CVE]
tags: [wordpress, cve, rce, sql-injection, rest-api]
description: "Giải thích dễ hiểu về chuỗi CVE-2026-63030 và CVE-2026-60137, phạm vi ảnh hưởng và các bước xử lý cho quản trị viên WordPress."
toc: true
---

> Bài viết phục vụ mục đích phòng thủ và nâng cao nhận thức. Nội dung không kèm payload hoặc quy trình khai thác trên hệ thống thực tế.

## Tóm tắt nhanh

`wp2shell` là tên cộng đồng đặt cho một chuỗi tấn công ghép từ hai lỗ hổng trong **WordPress Core**:

- **CVE-2026-63030**: lỗi nhầm lẫn tuyến xử lý (route confusion) trong Batch API của REST API.
- **CVE-2026-60137**: lỗi SQL Injection liên quan đến tham số `author__not_in` của `WP_Query`.

Điểm đáng sợ không phải chỉ là từng lỗi riêng lẻ, mà là cách chúng hỗ trợ nhau. Lỗi đầu có thể làm lớp kiểm tra đầu vào của REST API bị đi chệch; lỗi sau biến dữ liệu chưa được xử lý an toàn thành truy vấn cơ sở dữ liệu. Khi ghép lại trên phiên bản bị ảnh hưởng, kẻ tấn công **không cần tài khoản WordPress** vẫn có thể đi đến thực thi mã từ xa (RCE).

Nói ngắn gọn: đây là tình huống một người lạ có thể tìm được đường đi từ cửa API công khai đến quyền kiểm soát website. Vì vậy, hãy coi việc cập nhật là ưu tiên khẩn cấp.

## Thuật ngữ cần biết

- **REST API**: giao diện để ứng dụng hoặc trình duyệt gửi yêu cầu tới WordPress bằng HTTP.
- **SQL Injection (SQLi)**: dữ liệu đầu vào không an toàn làm thay đổi câu lệnh truy vấn cơ sở dữ liệu.
- **RCE (Remote Code Execution)**: kẻ tấn công có thể khiến máy chủ chạy mã theo ý họ từ xa.
- **Pre-authentication / pre-auth**: xảy ra trước khi đăng nhập; không cần tài khoản hợp lệ.

## Những phiên bản nào bị ảnh hưởng?

| Thành phần | Phiên bản bị ảnh hưởng | Bản đã vá |
| --- | --- | --- |
| Chuỗi `wp2shell` (hai CVE kết hợp) | WordPress 6.9.0–6.9.4, 7.0.0–7.0.1 | 6.9.5, 7.0.2 |
| CVE-2026-60137 riêng lẻ | WordPress 6.8.0–6.8.5, 6.9.0–6.9.4, 7.0.0–7.0.1 | 6.8.6, 6.9.5, 7.0.2 |

Nếu đang ở nhánh 6.8, lỗi SQLi vẫn cần được vá. Tuy nhiên, chuỗi RCE `wp2shell` được công bố cho các phiên bản 6.9 và 7.0 nêu trên. Với môi trường production, hãy ưu tiên nâng lên **một bản WordPress đang được hỗ trợ** thay vì chỉ dừng ở bản vá tối thiểu.

## Hai lỗi này hoạt động như thế nào?

### 1. CVE-2026-63030: request bị gửi nhầm nơi xử lý

WordPress có Batch API để gộp nhiều yêu cầu REST vào một lần gửi. Mỗi yêu cầu con phải được đối chiếu với đúng route và đúng quy tắc kiểm tra dữ liệu.

Ở phiên bản lỗi, một yêu cầu được tạo có chủ đích có thể làm các thông tin đối chiếu này **lệch nhau**. Hãy hình dung nhân viên bảo vệ kiểm tra thẻ của người A nhưng lại mở cửa dành cho người B: việc kiểm tra vẫn diễn ra, nhưng nó không còn bảo vệ đúng tài nguyên nữa.

Hệ quả là một request có thể đi vào handler không đúng như thiết kế và vượt qua một phần kiểm tra schema của REST API. Bản thân lỗi này rất nghiêm trọng vì nó làm suy yếu ranh giới mà API vốn dựa vào để tin cậy dữ liệu đầu vào.

### 2. CVE-2026-60137: dữ liệu lọt vào truy vấn SQL không đúng cách

`WP_Query` là thành phần WordPress dùng để tìm bài viết. Tham số `author__not_in` vốn được dùng để loại trừ bài viết của một số tác giả và đáng lẽ chỉ nhận danh sách mã số người dùng.

Trong trường hợp nhất định, giá trị không được ép kiểu và làm sạch đầy đủ trước khi được đưa vào phần điều kiện của truy vấn SQL. Nếu một plugin hoặc theme chuyển dữ liệu người dùng kiểm soát vào tham số này, nó có thể tạo ra SQL Injection.

Vì vậy, khi đứng một mình, CVE-2026-60137 thường cần một “đường dẫn hỗ trợ” từ plugin hoặc theme. Đây cũng là lý do advisory của WordPress mô tả lỗi này là *facilitated SQL injection*.

### 3. Khi ghép lại: `route confusion` mở đường cho SQLi

Trên WordPress 6.9 và 7.0 bị ảnh hưởng, lỗi Batch API tạo ra đường đi mà bình thường không nên có. Đường đi đó khiến dữ liệu có thể chạm tới `WP_Query` theo cách không còn được kiểm tra đúng. Từ đó, SQLi trở thành bàn đạp để leo thang thành chiếm quyền điều khiển website.

```text
Request ẩn danh
        ↓
Batch API đối chiếu sai route
        ↓
Kiểm tra dữ liệu bị áp dụng sai ngữ cảnh
        ↓
Dữ liệu chạm tới WP_Query không an toàn
        ↓
SQL Injection → leo thang đặc quyền → RCE
```

Sơ đồ trên chỉ mô tả quan hệ giữa các bước, không phải hướng dẫn khai thác. Điều quan trọng là: hai lớp bảo vệ tưởng chừng độc lập lại trở thành mắt xích cho nhau khi một trong số chúng bị lệch ngữ cảnh.

## Tác động thực tế là gì?

Nếu khai thác thành công, website có thể bị chiếm quyền mà không cần thông tin đăng nhập. Các hoạt động sau xâm nhập được quan sát trong thực tế gồm:

- tạo hoặc chiếm quyền một tài khoản quản trị;
- cài plugin độc hại hoặc backdoor để giữ quyền truy cập;
- liệt kê tài khoản người dùng để phục vụ các cuộc tấn công tiếp theo;
- truy cập trang quản trị và thay đổi nội dung, mã nguồn hoặc cấu hình website.

RCE không chỉ là “lỗi hiển thị dữ liệu”. Nó có thể kéo theo rò rỉ dữ liệu, phát tán mã độc sang khách truy cập, gửi spam, chiếm máy chủ hoặc dùng website làm điểm trung chuyển cho các tấn công khác.

## Cần làm gì ngay bây giờ?

### 1. Xác định phiên bản WordPress đang chạy

Kiểm tra trong **Dashboard → Updates** hoặc dùng WP-CLI nếu bạn quản trị máy chủ:

```bash
wp core version
```

Nếu site dùng 6.9.0–6.9.4 hoặc 7.0.0–7.0.1, hãy coi site có nguy cơ của toàn bộ chuỗi `wp2shell`. Với 6.8.0–6.8.5, hãy vá CVE-2026-60137.

### 2. Cập nhật WordPress Core

Mức vá tối thiểu được công bố là:

- 6.8.6 cho CVE-2026-60137;
- 6.9.5 cho cả hai lỗi trên nhánh 6.9;
- 7.0.2 cho cả hai lỗi trên nhánh 7.0.

Sao lưu trước khi cập nhật là hợp lý, nhưng đừng để quy trình sao lưu trở thành lý do trì hoãn vá lỗi. Hãy kiểm tra lại phiên bản sau cập nhật vì auto-update có thể bị tắt hoặc thất bại.

### 3. Giảm thiểu tạm thời nếu chưa thể vá

Giải pháp tạm thời là chặn request **ẩn danh** tới hai đường dẫn Batch API ở WAF hoặc reverse proxy:

```text
/wp-json/batch/v1
?rest_route=/batch/v1
```

Biện pháp này có thể làm hỏng một số chức năng hợp lệ phụ thuộc REST API, do đó chỉ dùng như lớp phòng vệ khẩn cấp. Nó **không thay thế cập nhật**.

### 4. Kiểm tra dấu hiệu đã bị xâm nhập

Sau khi vá, hãy kiểm tra theo mốc thời gian từ ngày công bố lỗ hổng đến khi site được cập nhật:

- tài khoản administrator mới hoặc thay đổi quyền bất thường;
- plugin, theme hoặc tệp PHP không rõ nguồn gốc;
- tệp PHP xuất hiện trong thư mục upload;
- log web có request bất thường tới Batch API, REST API, trang upload plugin hoặc khu vực quản trị;
- thay đổi bất thường trong `wp-config.php`, cron job, khóa xác thực và cấu hình database.

Một request đến Batch API chưa đủ kết luận website đã bị tấn công. Hãy đối chiếu nó với các dấu hiệu khác như tài khoản admin mới, plugin lạ hay thay đổi tệp để tránh cảnh báo nhầm.

Nếu nghi ngờ đã bị xâm nhập, cần cô lập site, lưu lại log và bằng chứng trước khi dọn dẹp, thay toàn bộ mật khẩu/secret liên quan, kiểm tra mã nguồn từ bản tin cậy và khôi phục từ bản sao lưu sạch khi cần. Việc chỉ xóa một tài khoản lạ thường không đủ để loại bỏ backdoor.

## Bài học kỹ thuật

`wp2shell` là ví dụ rất rõ về rủi ro của **vulnerability chaining**: một lỗi có mức độ vừa phải có thể trở thành rất nguy hiểm khi ghép với một lỗi khác.

Với đội ngũ phát triển, có ba điểm đáng ghi nhớ:

1. Xác thực request phải luôn gắn chặt với đúng route và đúng handler; không được để dữ liệu kiểm tra và dữ liệu thực thi bị lệch chỉ số hoặc lệch ngữ cảnh.
2. Dữ liệu đi vào truy vấn phải được ép kiểu, kiểm tra và truyền qua API an toàn ở mọi nhánh xử lý — không chỉ ở nhánh “thường dùng”.
3. Test bảo mật nên kiểm tra cả luồng ghép nhiều API hoặc nhiều thành phần, vì lỗi nghiêm trọng thường nằm ở điểm giao giữa chúng.

## Kết luận

Đây không phải là lỗi của một plugin hiếm gặp mà là WordPress Core. Nếu bạn vận hành WordPress trong dải phiên bản bị ảnh hưởng, hành động đúng là: **xác minh phiên bản, cập nhật ngay, rồi kiểm tra dấu hiệu xâm nhập**.

Chặn Batch API có thể giúp mua thời gian, nhưng bản vá mới là biện pháp xử lý triệt để. Trong các sự cố kiểu này, tốc độ cập nhật và khả năng kiểm tra hậu vá quan trọng không kém việc hiểu kỹ thuật khai thác.

## Tài liệu tham khảo

- [WordPress advisory: CVE-2026-63030 (GHSA-ff9f-jf42-662q)](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q)
- [WordPress advisory: CVE-2026-60137 (GHSA-fpp7-x2x2-2mjf)](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf)
- [Searchlight Cyber: wp2shell — Pre Authentication RCE in WordPress Core](https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core)
- [IPA: khuyến cáo về CVE-2026-60137 và CVE-2026-63030](https://www.ipa.go.jp/security/security-alert/2026/alert20260722.html)
- [Wiz Research: Exploitation in the Wild of wp2shell](https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137)
