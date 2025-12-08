require("dotenv").config();
const fs = require("fs");
const { PDFParse } = require("pdf-parse");
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

// Покращена функція витягування тексту з PDF
async function extractTextFromPDF(filePath) {
  try {
    console.log('[PDF] Початок витягування тексту з:', filePath);

    const dataBuffer = await fs.promises.readFile(filePath);

    // Використовуємо PDFParse v2 API
    const parser = new PDFParse({
      data: dataBuffer,
      verbosity: 0
    });

    try {
      const result = await parser.getText();
      const text = result.text?.trim();

      if (text && text.length > 10) {
        console.log(`[PDF] ✅ Успішно витягнуто ${text.length} символів`);
        console.log(`[PDF] Сторінок: ${result.pages?.length || 'невідомо'}`);
        return text;
      } else {
        console.warn('[PDF] ⚠️ Текст занадто короткий або порожній');
        return null;
      }
    } catch (parseError) {
      console.error('[PDF] Помилка парсингу:', parseError.message);
      return null;
    }

  } catch (error) {
    console.error('[PDF] Критична помилка витягування тексту:', error);
    return null;
  }
}

async function reprocessAllPDFs() {
  try {
    console.log('=== ПЕРЕОБРОБКА ВСІХ PDF ДОКУМЕНТІВ ===\n');

    const documents = await prisma.assetDocument.findMany({
      where: {
        mimeType: "application/pdf"
      }
    });

    console.log(`Знайдено ${documents.length} PDF документів\n`);

    let processed = 0;
    let withText = 0;
    let errors = 0;

    for (const doc of documents) {
      console.log(`\n--- Документ ${processed + 1}/${documents.length} ---`);
      console.log(`ID: ${doc.id}`);
      console.log(`Файл: ${doc.fileName}`);
      console.log(`Шлях: ${doc.filePath || 'невідомо'}`);

      try {
        if (doc.filePath && fs.existsSync(doc.filePath)) {
          const text = await extractTextFromPDF(doc.filePath);

          await prisma.assetDocument.update({
            where: { id: doc.id },
            data: { text }
          });

          processed++;
          if (text) {
            withText++;
            console.log(`✅ Успіх! Витягнуто ${text.length} символів`);
          } else {
            console.log(`⚠️ Текст не витягнуто (можливо сканований PDF)`);
          }
        } else {
          console.log(`❌ Файл не знайдено на диску`);
          errors++;
        }
      } catch (err) {
        console.error(`❌ Помилка переобробки:`, err.message);
        errors++;
      }
    }

    console.log('\n=== РЕЗУЛЬТАТ ===');
    console.log(`Всього документів: ${documents.length}`);
    console.log(`Оброблено: ${processed}`);
    console.log(`З текстом: ${withText}`);
    console.log(`Помилок: ${errors}`);

  } catch (error) {
    console.error('Критична помилка:', error);
  } finally {
    await prisma.$disconnect();
  }
}

reprocessAllPDFs();
