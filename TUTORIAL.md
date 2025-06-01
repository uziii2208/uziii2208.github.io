# Hướng Dẫn Sử Dụng Protected Content Feature

## Giới thiệu
Feature này cho phép bạn bảo vệ nội dung nhạy cảm trong bài viết bằng cách yêu cầu mật khẩu trước khi hiển thị. Cơ chế bảo vệ hoạt động hoàn toàn ở phía client-side, phù hợp cho các trang web tĩnh.

## Cách Triển Khai

### 1. Cấu trúc File
- File chính (ví dụ: `theseus.html`): Chứa giao diện và logic xử lý mật khẩu
- File nội dung được bảo vệ (ví dụ: `2e421a6054cdc10f0ef823a24b9a978a.html`): Chứa nội dung thực

### 2. Thiết lập Mật khẩu
1. Đặt giá trị `ENCRYPTED_KEY` trong script là chính MD5 hash mà bạn muốn sử dụng:
```javascript
const ENCRYPTED_KEY = '21d368f9af968770c0c9181d89cd4003'; // MD5 hash trực tiếp làm mật khẩu
```

### 3. Tùy Chỉnh Giao Diện
- Class CSS đã được thiết kế để phù hợp với theme hiện tại
- Bạn có thể điều chỉnh:
  - Màu sắc thông qua các class Tailwind
  - Nội dung hint
  - Kích thước khung hiển thị

### 4. Tính Năng Bảo Mật
- So sánh trực tiếp với MD5 hash để xác thực
- iframe được set với sandbox attributes để tăng bảo mật
- Nội dung được load động khi xác thực thành công
- CSP (Content Security Policy) được thêm vào file nội dung

## Cách Sử Dụng

### Thêm Protected Content Mới
1. Tạo file HTML chứa nội dung cần bảo vệ
2. Copy đoạn code protected content từ `theseus.html`
3. Thay đổi:
   - Đường dẫn file trong `iframe.src`
   - Mật khẩu trong `ENCRYPTED_KEY`
   - Nội dung hint nếu cần

### Ví dụ Code
```html
<div id="protected-content-wrapper" class="w-full h-screen bg-gray-800 p-4 rounded-2xl overflow-x-auto">
    <!-- Password Gate -->
    <div id="password-gate" class="flex flex-col items-center justify-center h-full">
        <!-- ... existing code ... -->
    </div>
    <div id="content-frame" class="hidden h-full"></div>
</div>

<script>
    const ENCRYPTED_KEY = 'your-md5-hash-here';
    // ... rest of the script ...
</script>
```

## Lưu ý Quan Trọng
1. **Bảo Mật**:
   - Feature này chỉ là basic protection
   - Không sử dụng cho nội dung cực kỳ nhạy cảm
   - Hash của mật khẩu có thể bị lộ trong source code

2. **SEO & Accessibility**:
   - Nội dung trong iframe không được index bởi search engines
   - Cân nhắc thêm meta description phù hợp

3. **Performance**:
   - Nội dung được load sau khi xác thực
   - Tối ưu kích thước file nội dung để tăng tốc độ load

## Troubleshooting
1. **Iframe không load:**
   - Kiểm tra đường dẫn file
   - Xác nhận CSP settings

2. **Lỗi JavaScript:**
   - Mở console để xem error messages
   - Kiểm tra syntax trong script

3. **Vấn đề style:**
   - Xác nhận các class Tailwind được load
   - Kiểm tra CSS conflicts

## Lưu Ý Về Bảo Mật (Dành Cho Người Dùng)

### Cách Tìm Mật Khẩu
Khi bạn gặp một trang được bảo vệ bằng mật khẩu, có một số cách để tìm mật khẩu:

1. **Kiểm Tra Source Code**
   - Mở source code của trang (Ctrl + U hoặc Right Click -> View Page Source)
   - Tìm kiếm các từ khóa như: "ENCRYPTED_KEY", "password", "hash", "md5"
   - Thường hash sẽ ở dạng: `21d368f9af968770c0c9181d89cd4003`

2. **Tìm File JavaScript**
   - Kiểm tra các file .js được import
   - Đặc biệt chú ý các file có tên liên quan đến trang hiện tại
   - Hash có thể được lưu trong biến như `ENCRYPTED_KEY` hoặc `correctPassword`

3. **Xử Lý Hash**
   - MD5 hash luôn có độ dài 32 ký tự
   - Có thể sử dụng trực tiếp hash làm mật khẩu
   - Không cần giải mã hash, chỉ cần copy và paste

### Mẹo Tìm Kiếm
- Sử dụng Chrome DevTools (F12)
- Tìm kiếm (Ctrl + F) với các pattern như:
  - `21d368` (phần đầu của hash)
  - `.js` (các file JavaScript)
  - `password` hoặc `key`
- Kiểm tra Network tab để xem các file được tải

### Bảo Vệ Nội Dung
Nếu bạn là người tạo nội dung:
1. Không để lộ hint quá rõ ràng
2. Đặt hash ở vị trí khó tìm thấy
3. Cân nhắc sử dụng các biện pháp bảo vệ khác
4. Thường xuyên thay đổi mật khẩu và hash
