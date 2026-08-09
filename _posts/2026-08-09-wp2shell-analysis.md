---
layout: post
title: "wp2shell: Khi hai lỗi WordPress ghép lại thành RCE không cần đăng nhập"
date: 2026-08-09 09:00:00 +0700
categories: [Security, CVE]
tags: [wordpress, cve, rce, sql-injection, rest-api]
description: "Giải thích dễ hiểu về chuỗi CVE-2026-63030 và CVE-2026-60137, phạm vi ảnh hưởng và các bước xử lý cho quản trị viên WordPress."
toc: true
---

> Bài viết phục vụ mục đích phòng thủ và nâng cao nhận thức. Nội dung giải thích cơ chế ở mức khái niệm, không kèm payload hoặc quy trình khai thác trên hệ thống thực tế.

## Đọc nhanh trong một phút

`wp2shell` không phải tên của một CVE đơn lẻ. Đây là tên gọi của một **chuỗi khai thác** trong WordPress Core, ghép từ hai lỗi:

- **CVE-2026-63030**: Batch API của REST API có thể ghép nhầm request với phần kiểm tra hoặc handler của request khác.
- **CVE-2026-60137**: `WP_Query` xử lý không an toàn dữ liệu đi vào tham số `author__not_in`, từ đó có thể dẫn đến SQL Injection.

Trên các phiên bản WordPress 6.9.x và 7.0.x bị ảnh hưởng, hai lỗi này có thể nối với nhau thành RCE (*Remote Code Execution*): người chưa đăng nhập có khả năng đi từ API công khai đến quyền kiểm soát website.

Điểm cần nhớ nhất: đây là lỗi trong **WordPress Core**, không phải một plugin hiếm gặp. Nếu site nằm trong dải phiên bản ảnh hưởng, hãy cập nhật trước rồi mới phân tích sâu.

## Một vài khái niệm tối thiểu

- **REST API** là cách ứng dụng gửi yêu cầu tới WordPress qua HTTP.
- **Batch API** cho phép đóng nhiều REST request nhỏ vào một request lớn.
- **SQL Injection (SQLi)** xảy ra khi input làm thay đổi câu lệnh truy vấn cơ sở dữ liệu.
- **RCE** là trạng thái nguy hiểm nhất: máy chủ chạy mã do người ở xa kiểm soát.
- **Pre-auth** nghĩa là không cần đăng nhập trước khi tấn công.

## Phiên bản nào cần quan tâm?

| Phạm vi | Phiên bản bị ảnh hưởng | Bản đã vá |
| --- | --- | --- |
| Chuỗi `wp2shell` đầy đủ | 6.9.0–6.9.4, 7.0.0–7.0.1 | 6.9.5, 7.0.2 |
| CVE-2026-60137 riêng lẻ | 6.8.0–6.8.5, 6.9.0–6.9.4, 7.0.0–7.0.1 | 6.8.6, 6.9.5, 7.0.2 |

Có một chi tiết dễ gây nhầm lẫn: **WordPress 6.8.0–6.8.5 vẫn có CVE-2026-60137**, nhưng không phải full chain `wp2shell` được công bố trên 6.9 và 7.0. Ở nhánh 6.8, SQLi thường cần plugin hoặc theme vô tình chuyển input không tin cậy vào `author__not_in`.

## Câu chuyện phía sau hai CVE

### Batch API: nhiều request, nhưng phải đúng ngữ cảnh

Hãy hình dung Batch API như một quầy tiếp nhận nhiều hồ sơ cùng lúc. Với mỗi hồ sơ, WordPress cần làm ba việc:

1. Xác định nó muốn đi tới route nào.
2. Chọn handler phù hợp để xử lý.
3. Kiểm tra method, quyền và dữ liệu đầu vào.

Ba kết quả này phải luôn thuộc về **cùng một request**. Nếu hồ sơ A được kiểm tra nhưng lại bị đưa cho người xử lý của hồ sơ B, thì kiểm tra vẫn tồn tại — chỉ là đang kiểm tra nhầm đối tượng.

Đó là bản chất của CVE-2026-63030: lỗi không đơn thuần là “thiếu kiểm tra quyền”, mà là **mất đồng bộ ngữ cảnh** giữa bước kiểm tra và bước thực thi.

### Nguyên nhân gốc: hai mảng bị lệch chỉ số

Trong batch handler, WordPress duy trì hai danh sách song song:

- `matches`: route/handler đã được tìm thấy cho từng request con;
- `validation`: kết quả kiểm tra tương ứng.

Với một path không được phân tích hợp lệ, lỗi được thêm vào `validation` nhưng handler tương ứng lại không được thêm vào `matches`. Từ thời điểm đó, cùng một vị trí trong hai danh sách có thể nói về **hai request khác nhau**.

```text
Request A lỗi đường dẫn  → validation có lỗi A, matches không có A
Request B hợp lệ         → handler B bị lệch lên vị trí của A

Kết quả: validation của A có thể bị ghép với handler của B
```

Đây là một bài học quan trọng khi thiết kế API: route parsing, permission check và input validation phải đi cùng một request object; không nên dựa vào nhiều mảng song song dễ lệch index.

### `WP_Query`: một tham số nhỏ có thể chạm vào SQL

`WP_Query` là lớp WordPress dùng để truy vấn bài viết. Tham số `author__not_in` có mục đích bình thường là loại các bài viết của một danh sách author ID.

Ở phiên bản bị ảnh hưởng, có đường xử lý không ép kiểu và làm sạch giá trị này đầy đủ trước khi nó tham gia tạo truy vấn SQL. Nếu dữ liệu do người dùng kiểm soát đi đến đây, nó có thể trở thành SQLi.

Khi đứng riêng lẻ, lỗi này thường cần plugin hoặc theme tạo ra đường gọi nói trên. Nhưng với WordPress 6.9+, CVE-2026-63030 đã biến một đường đi vốn không nên có thành cầu nối trực tiếp hơn tới primitive SQLi.

## Hai lỗi ghép lại thành `wp2shell` ra sao?

Không cần nhớ chi tiết từng request để hiểu chuỗi này. Hãy nhìn nó như một chuỗi ranh giới bảo vệ bị nối sai:

```text
Request chưa đăng nhập
        ↓
Batch API gán nhầm validation và handler
        ↓
Input được xử lý trong sai ngữ cảnh
        ↓
Chạm tới WP_Query và lỗi SQLi
        ↓
Đọc/điều khiển dữ liệu WordPress để leo thang đặc quyền
        ↓
Khả năng thực thi mã trên máy chủ
```

Mấu chốt là SQLi không tự động bằng RCE. RCE xuất hiện vì WordPress còn có các khả năng nghiệp vụ mạnh như quản lý user, lưu cấu hình và cài plugin. Khi attacker đã leo thang được quyền, những khả năng hợp lệ này có thể bị lạm dụng để kiểm soát site.

## Tác động với người vận hành WordPress

Một cuộc tấn công thành công không dừng ở việc xem dữ liệu. Kẻ tấn công có thể tạo tài khoản quản trị trái phép, cài plugin độc hại để duy trì truy cập, thay nội dung hoặc lấy thông tin phục vụ bước tấn công kế tiếp.

Vì vậy, với một site công khai đang chạy phiên bản bị ảnh hưởng, đây nên được xử lý như nguy cơ **chiếm quyền website**, không phải một cảnh báo thông thường trong backlog.

## Checklist xử lý ưu tiên

### 1. Kiểm tra phiên bản thực tế

Xem trong **Dashboard → Updates** hoặc dùng WP-CLI:

```bash
wp core version
```

Đừng chỉ dựa vào việc “có bật auto-update”. Hãy xác nhận phiên bản đang chạy trên server, vì bản cập nhật có thể bị tắt hoặc thất bại.

### 2. Vá lỗi trước

- Nhánh 7.0: nâng lên **7.0.2 hoặc mới hơn**.
- Nhánh 6.9: nâng lên **6.9.5 hoặc mới hơn**.
- Nhánh 6.8: nâng lên **6.8.6 hoặc mới hơn**.

Nên sao lưu trước, nhưng không trì hoãn cập nhật khi site đang exposed. Sau khi vá, kiểm tra lại version và tiếp tục bước rà soát compromise.

### 3. Chỉ dùng WAF làm giải pháp tạm thời

Khi chưa thể cập nhật ngay, có thể chặn request **ẩn danh** tới Batch API ở WAF hoặc reverse proxy:

```text
/wp-json/batch/v1
?rest_route=/batch/v1
```

Việc này có thể làm hỏng tính năng hợp lệ phụ thuộc REST API, nên chỉ là biện pháp khẩn cấp để mua thời gian. Bản vá mới là cách xử lý triệt để.

### 4. Rà soát dấu hiệu bị xâm nhập

Đặt mốc thời gian từ lúc công bố lỗ hổng đến lúc site được cập nhật, sau đó kiểm tra:

- tài khoản administrator mới hoặc quyền user thay đổi bất thường;
- plugin/theme không rõ nguồn gốc, đặc biệt thay đổi quanh thời điểm nghi vấn;
- tệp PHP xuất hiện bất thường trong thư mục upload hoặc web root;
- request bất thường tới Batch API, REST API, khu vực quản trị và plugin upload;
- thay đổi ở `wp-config.php`, cron job, khóa xác thực và thông tin kết nối database.

Một request tới Batch API không đủ để kết luận site đã bị tấn công. Hãy ghép bằng chứng: log, user mới, tệp mới và thay đổi cấu hình. Nếu có dấu hiệu compromise, cô lập site, lưu log trước khi dọn dẹp, xoay vòng mật khẩu/secret và khôi phục từ bản sao lưu sạch khi cần.

## Ba bài học cho đội phát triển

1. **Không tách rời ngữ cảnh request.** Kết quả parse route, validation và authorization phải luôn đi cùng nhau.
2. **Ép kiểu ở mọi nhánh xử lý.** Một tham số “đáng lẽ là danh sách số” vẫn cần được kiểm soát ngay cả ở nhánh ít được dùng.
3. **Kiểm thử điểm giao giữa các thành phần.** Những lỗi nguy hiểm thường không nằm trong một hàm đơn lẻ mà ở cách nhiều lớp tin tưởng lẫn nhau.

## Kết luận

`wp2shell` cho thấy một lỗi dispatch/validation có vẻ nhỏ có thể trở nên nghiêm trọng khi nó mở cửa cho SQLi và các khả năng sẵn có trong CMS. Nếu bạn quản trị WordPress, thứ tự hợp lý là: **xác minh phiên bản → vá lỗi → kiểm tra compromise → bổ sung phòng vệ dài hạn**.

Hiểu cơ chế giúp rút ra bài học thiết kế; còn với vận hành thực tế, hành động quan trọng nhất vẫn là cập nhật sớm và có khả năng kiểm chứng hậu vá.

## Tài liệu tham khảo

- [Tài liệu phân tích gốc trên Notion](https://app.notion.com/p/3aa5190c466980eba49aefbd0a2bd62e)
- [WordPress 7.0.2 Release](https://wordpress.org/news/2026/07/wordpress-7-0-2-release/)
- [WordPress advisory: CVE-2026-63030 (GHSA-ff9f-jf42-662q)](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q)
- [WordPress advisory: CVE-2026-60137 (GHSA-fpp7-x2x2-2mjf)](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf)
- [Searchlight Cyber: wp2shell — Pre Authentication RCE in WordPress Core](https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/)
- [Eye Security: wp2shell defenders guide](https://labs.eye.security/wp2shell-defenders-guide/)
