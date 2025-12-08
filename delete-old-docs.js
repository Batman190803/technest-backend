require("dotenv").config();
const fs = require("fs");
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

// Вкажіть ID документів які потрібно видалити
const DOCS_TO_DELETE = [1, 2, 3]; // Замініть на потрібні ID

async function deleteDocuments() {
  try {
    console.log('=== ВИДАЛЕННЯ СТАРИХ ДОКУМЕНТІВ ===\n');

    for (const docId of DOCS_TO_DELETE) {
      console.log(`\n--- Видалення документа ID ${docId} ---`);

      // Отримуємо документ
      const doc = await prisma.assetDocument.findUnique({
        where: { id: docId }
      });

      if (!doc) {
        console.log(`⚠️ Документ ${docId} не знайдено в БД`);
        continue;
      }

      console.log(`Файл: ${doc.fileName}`);
      console.log(`Шлях: ${doc.filePath || 'невідомо'}`);

      // Видаляємо файл з диску якщо він є
      if (doc.filePath && fs.existsSync(doc.filePath)) {
        try {
          fs.unlinkSync(doc.filePath);
          console.log('✅ Файл видалено з диску');
        } catch (err) {
          console.log('⚠️ Не вдалося видалити файл:', err.message);
        }
      } else {
        console.log('⚠️ Файл не знайдено на диску');
      }

      // Видаляємо запис з БД
      await prisma.assetDocument.delete({
        where: { id: docId }
      });
      console.log('✅ Запис видалено з БД');
    }

    console.log('\n=== ЗАВЕРШЕНО ===');
    console.log(`Видалено ${DOCS_TO_DELETE.length} документів`);

    // Показуємо що залишилось
    const remaining = await prisma.assetDocument.findMany({
      orderBy: { id: 'asc' }
    });

    console.log(`\nЗалишилось документів: ${remaining.length}`);
    if (remaining.length > 0) {
      remaining.forEach(doc => {
        console.log(`  - ID ${doc.id}: ${doc.fileName}`);
      });
    }

  } catch (error) {
    console.error('❌ Помилка:', error);
  } finally {
    await prisma.$disconnect();
  }
}

// ПОПЕРЕДЖЕННЯ
console.log('⚠️  УВАГА! Цей скрипт видалить документи з ID:', DOCS_TO_DELETE);
console.log('Якщо це не ті документи, змініть масив DOCS_TO_DELETE в скрипті.');
console.log('');

deleteDocuments();
