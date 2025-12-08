const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function checkDocs() {
  try {
    const docs = await prisma.assetDocument.findMany();
    console.log('=== ПЕРЕВІРКА ДОКУМЕНТІВ В БД ===');
    console.log('Загальна кількість документів:', docs.length);
    console.log('');

    docs.forEach((d, index) => {
      console.log(`Документ ${index + 1}:`);
      console.log('  ID:', d.id);
      console.log('  Файл:', d.fileName);
      console.log('  Тип:', d.mimeType);
      console.log('  Розмір:', d.fileSize ? `${(d.fileSize / 1024).toFixed(2)} KB` : 'невідомо');
      console.log('  Шлях:', d.filePath || 'не вказано');
      console.log('  Текст:', d.text ? `${d.text.length} символів` : '❌ НЕМАЄ ТЕКСТУ');
      if (d.text) {
        console.log('  Перші 200 символів:', d.text.substring(0, 200));
      }
      console.log('');
    });
  } catch (error) {
    console.error('Помилка:', error);
  } finally {
    await prisma.$disconnect();
  }
}

checkDocs();
