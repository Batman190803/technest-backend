// Скрипт для тестування витягування тексту з PDF
const fs = require('fs');
const { PDFParse } = require('pdf-parse');

async function testPDF() {
  try {
    // Створимо простий текстовий PDF для тестування
    const PDFDocument = require('pdfkit');
    const testPdfPath = './test-sample.pdf';

    // Створюємо PDF
    const doc = new PDFDocument();
    doc.pipe(fs.createWriteStream(testPdfPath));

    doc.fontSize(16).text('Тестовий PDF документ', 100, 100);
    doc.fontSize(12).text('Це тестовий документ для перевірки витягування тексту.', 100, 150);
    doc.text('Технічні характеристики обладнання:', 100, 180);
    doc.text('- Процесор: Intel Core i7', 100, 200);
    doc.text('- Оперативна пам\'ять: 16 GB', 100, 220);
    doc.text('- Жорсткий диск: 512 GB SSD', 100, 240);

    doc.end();

    // Чекаємо завершення запису
    await new Promise(resolve => setTimeout(resolve, 1000));

    console.log('✅ PDF створено:', testPdfPath);

    // Тестуємо витягування тексту
    const dataBuffer = fs.readFileSync(testPdfPath);
    const parser = new PDFParse();
    const data = await parser.parse(dataBuffer);

    console.log('\n=== РЕЗУЛЬТАТ ВИТЯГУВАННЯ ===');
    console.log('Кількість сторінок:', data.numpages);
    console.log('Кількість символів:', data.text.length);
    console.log('\n=== ТЕКСТ ===');
    console.log(data.text);

    // Видаляємо тестовий файл
    fs.unlinkSync(testPdfPath);
    console.log('\n✅ Тестовий файл видалено');

  } catch (error) {
    console.error('❌ Помилка:', error);
  }
}

testPDF();
