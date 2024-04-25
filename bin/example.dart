import 'recode.dart';

void main(){
  Kyz kyznechik = Kyz();
  String textInput = "hello";//Текст
  String keyInput = "1234";
  String textEncrypt = kyznechik.encrypt(textInput, kyznechik.getKeys(keyInput));
  String textDecrypt = kyznechik.decrypt(textEncrypt, kyznechik.getKeys(keyInput));
  print(textEncrypt);// Вывод зашифрованного текста
  print(textDecrypt);// Вывод расшифрованного текста
}