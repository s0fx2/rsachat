import PySimpleGUI as sg
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import pyperclip
import os
import json
from PIL import Image
import numpy as np
import logging
import bcrypt
from cryptography.hazmat.backends import default_backend

# 在文件开头修改日志配置
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 创建publickey和privatekey目录
if not os.path.exists('publickey'):
    os.makedirs('publickey')
if not os.path.exists('privatekey'):
    os.makedirs('privatekey')

# 定义更大的字体
FONT = ("Any", 28)
BUTTON_FONT = ("Any", 24)

def generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key

def export_public_key(private_key):
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode()

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

def export_private_key(private_key, passphrase):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
    )
    return pem.decode(), hash_password(passphrase)

def import_private_key(key_data, passphrase, stored_hash=None):
    if stored_hash is not None:
        if not check_password(passphrase, stored_hash):
            logging.error("密码验证失败")
            raise ValueError("密码不正确")
        else:
            logging.info("密码验证成功")
    try:
        private_key = serialization.load_pem_private_key(
            key_data.encode(),
            password=passphrase.encode(),
            backend=default_backend()
        )
        logging.info("成功导入私钥")
        return private_key
    except ValueError:
        logging.error("导入私钥失败，可能是密码错误")
        raise ValueError("导入私钥失败，可能是密码错误")
    except Exception:
        logging.error("导入私钥时发生未知错误")
        raise ValueError("导入私钥时发生未知错误")

def import_public_key(key_data):
    return serialization.load_pem_public_key(key_data.encode())

def encrypt_message(public_key, message):
    try:
        logging.info("开始加密消息")
        encrypted = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encoded = base64.b64encode(encrypted).decode()
        logging.info("加密完成")
        return encoded
    except Exception:
        logging.error("加密消息时出错")
        raise

def decrypt_message(private_key, encrypted_message):
    try:
        decrypted = private_key.decrypt(
            base64.b64decode(encrypted_message),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()
    except Exception:
        logging.error("解密消息时出错")
        raise ValueError("解密失败，可能是密文格式不正确或私钥不匹配")

def save_private_key(name, key_data, hashed_passphrase):
    filename = os.path.join('privatekey', f"{name}.pem")
    try:
        with open(filename, 'w') as f:
            json.dump({
                'key': base64.b64encode(key_data.encode()).decode(),
                'hash': base64.b64encode(hashed_passphrase).decode()
            }, f)
        logging.info(f"成功保存私钥：{name}")
    except Exception as e:
        logging.error(f"保存私钥时出错：{str(e)}")
        raise

def load_private_keys():
    keys = {}
    for filename in os.listdir('privatekey'):
        if filename.endswith('.pem'):
            name = os.path.splitext(filename)[0]
            try:
                with open(os.path.join('privatekey', filename), 'r') as f:
                    data = json.load(f)
                    keys[name] = {
                        'key': base64.b64decode(data['key']).decode(),
                        'hash': base64.b64decode(data['hash'])
                    }
                logging.info(f"成功加载私钥：{name}")
            except Exception as e:
                logging.error(f"加载私钥文件 {filename} 时出错：{str(e)}")
                continue
    return keys

def save_public_key(name, key_data):
    filename = os.path.join('publickey', f"{name}.pem")
    with open(filename, 'w') as f:
        f.write(key_data)

def load_public_keys():
    keys = {}
    for filename in os.listdir('publickey'):
        if filename.endswith('.pem'):
            name = os.path.splitext(filename)[0]
            with open(os.path.join('publickey', filename), 'r') as f:
                key_data = f.read()
            keys[name] = key_data
    return keys

public_keys = load_public_keys()
private_keys = load_private_keys()

def update_key_list(window):
    window['-KEY_LIST-'].update(values=list(public_keys.keys()))
    window['-RECIPIENT-'].update(values=list(public_keys.keys()))
    window['-STEG_RECIPIENT-'].update(values=list(public_keys.keys()))
    window['-PRIVATE_KEY-'].update(values=list(private_keys.keys()))
    window['-STEG_PRIVATE_KEY-'].update(values=list(private_keys.keys()))

def create_layout():
    tab_group = sg.TabGroup([
        [sg.Tab('密钥管理', [
            [sg.Text('生成新密钥对:', font=FONT)],
            [sg.Text('姓名:', font=FONT, size=(10, 1)), sg.Input(key='-NAME-', font=FONT, expand_x=True)],
            [sg.Text('邮箱:', font=FONT, size=(10, 1)), sg.Input(key='-EMAIL-', font=FONT, expand_x=True)],
            [sg.Text('密码:', font=FONT, size=(10, 1)), sg.Input(key='-PASSPHRASE-', password_char='*', font=FONT, expand_x=True)],
            [sg.Button('生成密钥对', font=BUTTON_FONT, expand_x=True)],
            [sg.Text('密钥ID:', font=FONT, size=(10, 1)), sg.Input(key='-KEY_ID-', disabled=True, font=FONT, expand_x=True)],
            [sg.Button('导出公钥', font=BUTTON_FONT, expand_x=True), sg.Button('导入公钥', font=BUTTON_FONT, expand_x=True)],
            [sg.Text('公钥列表:', font=FONT)],
            [sg.Listbox(values=list(public_keys.keys()), size=(30, 6), key='-KEY_LIST-', font=FONT, expand_x=True, expand_y=True)],
            [sg.Button('删除选中公钥', font=BUTTON_FONT, expand_x=True)]
        ], font=FONT)],
        [sg.Tab('加密', [
            [sg.Text('选择接收者:', font=FONT), sg.Combo(list(public_keys.keys()), key='-RECIPIENT-', font=FONT, expand_x=True)],
            [sg.Text('明文消息:', font=FONT)],
            [sg.Multiline(key='-PLAINTEXT-', size=(50, 5), font=FONT, expand_x=True, expand_y=True)],
            [sg.Button('加密', font=BUTTON_FONT, expand_x=True)],
            [sg.Text('加后的消息:', font=FONT)],
            [sg.Multiline(key='-CIPHERTEXT-', size=(50, 5), disabled=True, font=FONT, expand_x=True, expand_y=True)]
        ], font=FONT)],
        [sg.Tab('解密', [
            [sg.Text('选择私钥:', font=FONT), sg.Combo(list(private_keys.keys()), key='-PRIVATE_KEY-', font=FONT, expand_x=True)],
            [sg.Text('密文:', font=FONT)],
            [sg.Multiline(key='-CIPHERTEXT_TO_DECRYPT-', size=(50, 5), font=FONT, expand_x=True, expand_y=True)],
            [sg.Text('密码:', font=FONT), sg.Input(key='-DECRYPT_PASSPHRASE-', password_char='*', font=FONT, expand_x=True)],
            [sg.Button('解密', font=BUTTON_FONT, expand_x=True)],
            [sg.Text('解密后的消息:', font=FONT)],
            [sg.Multiline(key='-DECRYPTED_TEXT-', size=(50, 5), disabled=True, font=FONT, expand_x=True, expand_y=True)]
        ], font=FONT)],
        [sg.Tab('图像隐写', [
            [sg.Text('选择图片:', font=FONT), sg.Input(key='-IMAGE_PATH-', font=FONT), 
             sg.FileBrowse(font=BUTTON_FONT, file_types=(("PNG Files", "*.png"), ("JPEG Files", "*.jpg *.jpeg")))],
            [sg.Text('选择接收者:', font=FONT), sg.Combo(list(public_keys.keys()), key='-STEG_RECIPIENT-', font=FONT, expand_x=True)],
            [sg.Text('明文消息:', font=FONT)],
            [sg.Multiline(key='-STEG_PLAINTEXT-', size=(50, 5), font=FONT, expand_x=True, expand_y=True)],
            [sg.Button('加密并隐写', font=BUTTON_FONT, expand_x=True)],
            [sg.HorizontalSeparator()],
            [sg.Text('解密设置:', font=FONT)],
            [sg.Text('选择私钥:', font=FONT), sg.Combo(list(private_keys.keys()), key='-STEG_PRIVATE_KEY-', font=FONT, expand_x=True)],
            [sg.Text('密码:', font=FONT), sg.Input(key='-STEG_DECRYPT_PASSPHRASE-', password_char='*', font=FONT, expand_x=True)],
            [sg.Button('从图片解密', font=BUTTON_FONT, expand_x=True)],
            [sg.Text('解密后的消息:', font=FONT)],
            [sg.Multiline(key='-STEG_DECRYPTED_TEXT-', size=(50, 5), disabled=True, font=FONT, expand_x=True, expand_y=True)]
        ], font=FONT)],
        [sg.Tab('日志', [
            [sg.Multiline(size=(80, 20), key='-LOG_OUTPUT-', font=FONT, expand_x=True, expand_y=True, autoscroll=True, disabled=True)]
        ], font=FONT)]
    ], font=FONT, expand_x=True, expand_y=True, key='-TABGROUP-')

    layout = [
        [sg.Text('RSA加密解密应用', font=("Any", 36, "bold"), justification='center', expand_x=True)],
        [tab_group],
        [sg.Button('关闭', font=BUTTON_FONT, expand_x=True, key='-CLOSE-')]
    ]
    return layout

def encode_message_in_image(image_path, message):
    try:
        img = Image.open(image_path)
        logging.info(f"成功打开图片: {image_path}")
        width, height = img.size
        array = np.array(list(img.getdata()))

        if img.mode == 'RGB':
            n = 3
        elif img.mode == 'RGBA':
            n = 4
        else:
            raise ValueError(f"不支持的图片模式: {img.mode}")

        logging.info(f"图模式: {img.mode}, 尺寸: {width}x{height}")

        total_pixels = array.size // n
        logging.info(f"总像素数: {total_pixels}")

        message += "≠≠≠"  # 添加结束标记
        b_message = ''.join([format(ord(i), "08b") for i in message])
        req_pixels = len(b_message)

        logging.info(f"消息长度: {len(message)}, 二进制长度: {req_pixels}")

        if req_pixels > total_pixels * 3:
            raise ValueError(f"消息太长，需要 {req_pixels} 位，但图片只能存储 {total_pixels * 3} 位")

        index = 0
        for p in range(total_pixels):
            for q in range(0, 3):
                if index < req_pixels:
                    array[p][q] = (array[p][q] & 0xFE) | int(b_message[index])
                    index += 1

        logging.info(f"已嵌入 {index} 位数据")

        array = array.reshape((height, width, n))
        enc_img = Image.fromarray(array.astype('uint8'), img.mode)
        logging.info("成功创建包含隐写消息的新图像")
        return enc_img
    except Exception as e:
        logging.error(f"图像隐��过程中出错: {str(e)}")
        raise

def decode_message_from_image(image_path):
    try:
        img = Image.open(image_path)
        logging.info(f"成功打开图片: {image_path}")
        array = np.array(list(img.getdata()))
        logging.info(f"图片模式: {img.mode}, 数组形状: {array.shape}")

        if img.mode == 'RGB':
            n = 3
        elif img.mode == 'RGBA':
            n = 4
        else:
            raise ValueError(f"不支持的图片模式: {img.mode}")

        total_pixels = array.size // n
        logging.info(f"总像素数: {total_pixels}")

        hidden_bits = ""
        for p in range(total_pixels):
            for q in range(0, 3):
                hidden_bits += str(array[p][q] & 1)

        hidden_bytes = [hidden_bits[i:i+8] for i in range(0, len(hidden_bits), 8)]
        message = ""
        for i, byte in enumerate(hidden_bytes):
            if len(byte) != 8:
                continue
            char = chr(int(byte, 2))
            message += char
            if message.endswith("≠≠≠"):
                logging.info(f"在位置 {len(message)} 找到结束标记")
                return message[:-3]
            if i % 10000 == 0:
                logging.debug(f"已处理 {i} 个字节，当前消息长度: {len(message)}")
            if len(message) > 1000000:  # 设置一个合理的上限
                logging.warning(f"消息长度超过1,000,000字符，可能存在问题。")
                break

        # 如果没有找到结束标记，尝试查找base64编码的内容
        import re
        base64_pattern = r'([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)'
        matches = re.finditer(base64_pattern, message)
        longest_match = max(matches, key=lambda x: len(x.group(0)), default=None)
        if longest_match:
            potential_message = longest_match.group(0)
            logging.info(f"找到潜在的base64编码消息，长度: {len(potential_message)}")
            return potential_message

        logging.warning(f"未找到结束标记或有效的base64编码。消息长度: {len(message)}，前100个字符: {message[:100]}")
        return ""
    except Exception as e:
        logging.error(f"解码图片消息时出错: {str(e)}")
        raise

class GUILogHandler(logging.Handler):
    def __init__(self, window):
        super().__init__()
        self.window = window

    def emit(self, record):
        log_entry = self.format(record)
        self.window.write_event_value('-LOG-', log_entry)
        # 强制更新GUI
        self.window.refresh()

def main():
    layout = create_layout()
    window = sg.Window('RSA加密解密应用', layout, font=FONT, size=(1200, 920), resizable=False, finalize=True)

    # 设置日志处理器
    gui_handler = GUILogHandler(window)
    gui_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logging.getLogger().addHandler(gui_handler)
    logging.getLogger().setLevel(logging.INFO)

    # 添加一条测试日志
    logging.info("应用程序启动")

    # 检查是否存在私钥
    if not private_keys:
        logging.warning("没有找到任何私钥")
        sg.popup_ok("没有找到任何私钥。请先创建一个新的密钥对。", font=FONT, title="提示")
        window['-NAME-'].set_focus()

    while True:
        event, values = window.read()  # 移除超时
        if event in (sg.WINDOW_CLOSED, '-CLOSE-'):
            break
        elif event == '-LOG-':
            window['-LOG_OUTPUT-'].print(values['-LOG-'])
        elif event == '生成密钥对':
            try:
                logging.info("开始生成密钥对")
                name = values['-NAME-']
                email = values['-EMAIL-']
                passphrase = values['-PASSPHRASE-']
                if not name or not email or not passphrase:
                    sg.popup_error('请填写所有必要的信息（姓名、邮箱和密码）', font=FONT)
                else:
                    private_key = generate_key()
                    public_key = export_public_key(private_key)
                    private_key_pem, hashed_passphrase = export_private_key(private_key, passphrase)
                    save_public_key(name, public_key)
                    save_private_key(name, private_key_pem, hashed_passphrase)
                    public_keys[name] = public_key
                    private_keys[name] = {'key': private_key_pem, 'hash': hashed_passphrase}
                    window['-KEY_ID-'].update(public_key[:30] + '...')
                    update_key_list(window)
                    sg.popup('密钥对已生成并保存', font=FONT)
                    logging.info(f"密钥对已生成并保存：{name}")
            except Exception as e:
                logging.error(f"生成密钥对时出错：{str(e)}")
                sg.popup_error(f'生成密钥对时出错：{str(e)}', font=FONT)
        elif event == '导出公钥':
            try:
                selected_key = values['-KEY_LIST-'][0]
                if selected_key:
                    public_key = public_keys[selected_key]
                    sg.popup_scrolled(public_key, title='公', font=FONT)
                    pyperclip.copy(public_key)
                    sg.popup('公钥已复制到剪贴板', font=FONT)
                else:
                    sg.popup_error('先选择一个公钥', font=FONT)
            except Exception as e:
                sg.popup_error(f'导出公钥时出错：{str(e)}', font=FONT)
        elif event == '导入公钥':
            try:
                name = sg.popup_get_text('请输入公钥名称:', title='导入公', font=FONT)
                if name:
                    key_data = sg.popup_get_text('请粘贴公钥数据:', title='导入公钥', font=FONT)
                    if key_data:
                        import_public_key(key_data)
                        save_public_key(name, key_data)
                        public_keys[name] = key_data
                        update_key_list(window)
                        sg.popup('公钥已成功导入', font=FONT)
            except Exception as e:
                sg.popup_error(f'导入公钥时出错：{str(e)}', font=FONT)
        elif event == '删除选中公钥':
            try:
                selected_key = values['-KEY_LIST-'][0]
                if selected_key:
                    del public_keys[selected_key]
                    os.remove(os.path.join('publickey', f"{selected_key}.pem"))
                    update_key_list(window)
                    sg.popup(f'已删除公钥：{selected_key}', font=FONT)
            except Exception as e:
                sg.popup_error(f'删除公钥时出错：{str(e)}', font=FONT)
        elif event == '加密':
            try:
                recipient_name = values['-RECIPIENT-']
                plaintext = values['-PLAINTEXT-']
                if not recipient_name or not plaintext:
                    sg.popup_error('请选择接收者并输入明文消息', font=FONT)
                else:
                    logging.info(f"开始加密过程：接收者={recipient_name}, 明文长度={len(plaintext)}")
                    recipient_key = public_keys[recipient_name]
                    public_key = import_public_key(recipient_key)
                    logging.info("成功导入公钥")
                    ciphertext = encrypt_message(public_key, plaintext)
                    window['-CIPHERTEXT-'].update(ciphertext)
                    pyperclip.copy(ciphertext)
                    logging.info("加密完成，密文已复制到剪贴板")
                    sg.popup('消息已加密并复制到剪贴板', font=FONT)
            except Exception:
                logging.error("加密消息时出错")
                sg.popup_error('加密消息时出错', font=FONT)
        elif event == '解密':
            if not private_keys:
                sg.popup_ok("没有找到任何私钥。请先创建一个新的密钥对。", font=FONT, title="提示")
                window['-NAME-'].set_focus()
                continue
            try:
                private_key_name = values['-PRIVATE_KEY-']
                ciphertext = values['-CIPHERTEXT_TO_DECRYPT-']
                passphrase = values['-DECRYPT_PASSPHRASE-']
                if not private_key_name or not ciphertext or not passphrase:
                    sg.popup_error('请选择私钥、输入密文和密码', font=FONT)
                else:
                    logging.info(f"尝试解密：私钥名称={private_key_name}, 密文长度={len(ciphertext)}")
                    private_key_data = private_keys[private_key_name]['key']
                    stored_hash = private_keys[private_key_name]['hash']
                    try:
                        if stored_hash is None:
                            logging.warning("未找到存储的哈希值，跳过密码验证")
                            private_key = import_private_key(private_key_data, passphrase)
                        else:
                            private_key = import_private_key(private_key_data, passphrase, stored_hash)
                        decrypted = decrypt_message(private_key, ciphertext)
                        window['-DECRYPTED_TEXT-'].update(decrypted)
                        logging.info("消息解密成功")
                        sg.popup('消息已解密', font=FONT)
                    except ValueError:
                        logging.error("解密失败")
                        sg.popup_error('解密失败', font=FONT)
                    except Exception:
                        logging.error("解密消息时出错")
                        sg.popup_error('解密消息时出错', font=FONT)
            except Exception:
                logging.error("解密过程中发生未知错误")
                sg.popup_error('解密过程中发生未知错误', font=FONT)
        elif event == '加密并隐写':
            try:
                image_path = values['-IMAGE_PATH-']
                recipient_name = values['-STEG_RECIPIENT-']
                plaintext = values['-STEG_PLAINTEXT-']
                if not image_path or not recipient_name or not plaintext:
                    sg.popup_error('请选择图片、接收者和输入明文消息', font=FONT)
                else:
                    logging.info(f"开始加密并隐写过程: 图片路径={image_path}, 接收者={recipient_name}")
                    recipient_key = public_keys[recipient_name]
                    public_key = import_public_key(recipient_key)
                    ciphertext = encrypt_message(public_key, plaintext)
                    logging.info(f"加密后的密文长度: {len(ciphertext)}")
                    enc_img = encode_message_in_image(image_path, ciphertext)
                    save_path = sg.popup_get_file('保存加密后的图片', save_as=True, file_types=(("PNG Files", "*.png"), ("JPEG Files", "*.jpg *.jpeg")), font=FONT)
                    if save_path:
                        if not save_path.lower().endswith(('.png', '.jpg', '.jpeg')):
                            save_path += '.png'  # 默认使用PNG格式
                        enc_img.save(save_path)
                        logging.info(f"加密的图片已保存到: {save_path}")
                        sg.popup('加密的消息已隐写到图片中', font=FONT)
            except Exception:
                logging.error("加密并隐写消息时出错")
                sg.popup_error('加密并隐写消息时出错', font=FONT)
        elif event == '从图片解密':
            if not private_keys:
                sg.popup_ok("没有找到任何私钥。请先创建一个新的密钥对。", font=FONT, title="提示")
                window['-NAME-'].set_focus()
                continue
            try:
                image_path = values['-IMAGE_PATH-']
                private_key_name = values['-STEG_PRIVATE_KEY-']
                passphrase = values['-STEG_DECRYPT_PASSPHRASE-']
                if not image_path or not private_key_name or not passphrase:
                    sg.popup_error('请选择图片、私钥和输入密码', font=FONT)
                else:
                    logging.info(f"开始从图片解密: {image_path}")
                    ciphertext = decode_message_from_image(image_path)
                    if not ciphertext:
                        logging.warning("无法从图片中提取加密消息")
                        sg.popup_error('无法从图片中提取加密消息。请确保选择了正确的图片，并且图片中包含隐写的消息。', font=FONT)
                    else:
                        logging.info(f"成功从图片中提取密文，长度: {len(ciphertext)}")
                        try:
                            private_key_data = private_keys[private_key_name]['key']
                            stored_hash = private_keys[private_key_name]['hash']
                            if stored_hash is None:
                                private_key = import_private_key(private_key_data, passphrase)
                            else:
                                private_key = import_private_key(private_key_data, passphrase, stored_hash)
                            decrypted = decrypt_message(private_key, ciphertext)
                            window['-STEG_DECRYPTED_TEXT-'].update(decrypted)
                            logging.info("消息解密成功")
                            sg.popup('消息已从图片中解密', font=FONT)
                        except ValueError:
                            logging.error("解密失败")
                            sg.popup_error('解密失败', font=FONT)
                        except Exception:
                            logging.error("解密提取的消息时出错")
                            sg.popup_error('解密提取消息时出错', font=FONT)
            except Exception:
                logging.error("从图片解密消息时出错")
                sg.popup_error('从图片解密消息时出错', font=FONT)

    window.close()

if __name__ == '__main__':
    main()