require("dotenv").config();
const fs = require("fs");
const { PDFParse } = require("pdf-parse");

async function testExtract() {
  try {
    console.log('=== ТЕСТ ВИТЯГУВАННЯ ТЕКСТУ З PDF ===\n');

    // Створюємо простий тестовий PDF
    const PDFDocument = require('pdfkit');
    const testPath = './test-document.pdf';

    const doc = new PDFDocument();
    doc.pipe(fs.createWriteStream(testPath));

    doc.fontSize(16).text('Інструкція з обслуговування комп\'ютера', 100, 100);
    doc.fontSize(12).text('', 100, 140);
    doc.text('1. Технічні характеристики:', 100, 160);
    doc.text('   - Процесор: Intel Core i7-12700K', 100, 180);
    doc.text('   - Оперативна пам\'ять: 32 GB DDR4', 100, 200);
    doc.text('   - SSD: 1 TB NVMe', 100, 220);
    doc.text('', 100, 240);
    doc.text('2. Порядок технічного обслуговування:', 100, 260);
    doc.text('   - Очищення від пилу: щомісяця', 100, 280);
    doc.text('   - Перевірка системи охолодження: щоквартально', 100, 300);
    doc.text('   - Оновлення ПЗ: щомісяця', 100, 320);

    doc.end();

    // Чекаємо завершення запису
    await new Promise(resolve => setTimeout(resolve, 1000));

    console.log('✅ Тестовий PDF створено\n');

    // Тестуємо витягування
    const dataBuffer = fs.readFileSync(testPath);
    const parser = new PDFParse({
      data: dataBuffer,
      verbosity: 0
    });

    console.log('📄 Витягування тексту...\n');
    const result = await parser.getText();

    console.log('=== РЕЗУЛЬТАТ ===');
    console.log('Сторінок:', result.pages || result.numpages || 'невідомо');
    console.log('Символів:', result.text.length);
    console.log('\n=== ВИТЯГНУТИЙ ТЕКСТ ===');
    console.log(result.text);
    console.log('\n✅ Тест успішний!');

    // Видаляємо тестовий файл
    fs.unlinkSync(testPath);

  } catch (error) {
    console.error('❌ Помилка:', error);
  }
}

testExtract();
