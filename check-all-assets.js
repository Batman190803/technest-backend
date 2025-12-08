require("dotenv").config();
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

async function checkAllAssets() {
  try {
    console.log('=== ПЕРЕВІРКА ВСІХ АКТИВІВ ===\n');

    const allAssets = await prisma.asset.findMany({
      orderBy: { id: 'asc' }
    });

    console.log(`Знайдено ${allAssets.length} активів в базі даних\n`);

    if (allAssets.length > 0) {
      allAssets.forEach((asset, index) => {
        console.log(`--- Актив ${index + 1} ---`);
        console.log(`ID: ${asset.id}`);
        console.log(`Назва: ${asset.name}`);
        console.log(`Інв. номер: ${asset.inventoryNumber}`);
        console.log(`Категорія ID: ${asset.categoryId}`);
        console.log(`User ID: ${asset.userId}`);
        if (asset.model) console.log(`Модель: ${asset.model}`);
        if (asset.room) console.log(`Кімната: ${asset.room}`);
        if (asset.responsible) console.log(`Відповідальний: ${asset.responsible}`);
        console.log('');
      });
    } else {
      console.log('⚠️ В базі даних немає жодного активу!');
      console.log('Активи не були створені через мобільний додаток.');
    }

  } catch (error) {
    console.error('Помилка:', error);
  } finally {
    await prisma.$disconnect();
  }
}

checkAllAssets();
