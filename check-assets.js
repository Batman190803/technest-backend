require("dotenv").config();
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

async function checkAssets() {
  try {
    console.log('=== ПЕРЕВІРКА АКТИВІВ В БД ===\n');

    // Отримуємо всі категорії з активами
    const categories = await prisma.assetCategory.findMany({
      include: {
        assets: true,
        _count: {
          select: { assets: true }
        }
      },
      orderBy: {
        id: 'asc'
      }
    });

    console.log(`Знайдено ${categories.length} категорій\n`);

    categories.forEach((cat, index) => {
      console.log(`--- Категорія ${index + 1} ---`);
      console.log(`ID: ${cat.id}`);
      console.log(`Назва: ${cat.title}`);
      console.log(`User ID: ${cat.userId}`);
      console.log(`Кількість активів: ${cat._count.assets}`);

      if (cat.assets.length > 0) {
        console.log('\nАктиви в цій категорії:');
        cat.assets.forEach((asset, i) => {
          console.log(`  ${i + 1}. ${asset.name} (Інв.№ ${asset.inventoryNumber})`);
          if (asset.model) console.log(`     Модель: ${asset.model}`);
          if (asset.room) console.log(`     Кімната: ${asset.room}`);
          if (asset.responsible) console.log(`     Відповідальний: ${asset.responsible}`);
        });
      } else {
        console.log('⚠️ КАТЕГОРІЯ ПОРОЖНЯ - немає активів');
      }
      console.log('');
    });

    // Загальна статистика
    const totalAssets = categories.reduce((sum, cat) => sum + cat.assets.length, 0);
    console.log('=== ЗАГАЛЬНА СТАТИСТИКА ===');
    console.log(`Всього категорій: ${categories.length}`);
    console.log(`Всього активів: ${totalAssets}`);
    console.log(`Порожніх категорій: ${categories.filter(c => c.assets.length === 0).length}`);

  } catch (error) {
    console.error('Помилка:', error);
  } finally {
    await prisma.$disconnect();
  }
}

checkAssets();
