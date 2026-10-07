// Owner decision cards. Text follows development/decisions/M1-OWNER-DECISIONS-AR.md and the
// M1 drafts. These are recommendations, never approvals: an answer is stored durably,
// queued for the host coordinator, and only becomes a recorded owner answer after the
// coordinator acknowledges it. Nothing here changes M1 policy automatically.

export const OWNER_QUESTIONS = [
  {
    id: 'U01', titleAr: 'عنوان عقد المصنع',
    questionAr: 'هل يكون عنوان المصنع الكامل 0x0000000000000000000000000000000000c0c005؟',
    whyAr: 'المصدر يذكر العنوان مختصرًا (0x…C0C005)، والمتجهات الحالية مبنية على هذا التوسيع.',
    recommendationAr: 'التأكيد، لأن كل المتجهات المحسوبة تفترضه.',
    options: [
      { id: 'confirm', labelAr: 'أؤكد هذا العنوان', consequenceAr: 'تبقى المتجهات كما هي.' },
      { id: 'other', labelAr: 'عنوان آخر (اكتبه في الملاحظة)', consequenceAr: 'يجب إعادة توليد كل المتجهات المعتمدة على العنوان.' },
    ],
  },
  {
    id: 'U02', titleAr: 'عرض إصدار ملغى عند طلبه صراحة',
    questionAr: 'هل يُسمح بعرض إصدار ملغى عندما يطلبه المستخدم صراحة بـ @v<n>؟',
    whyAr: 'الأساس يمنع العرض الافتراضي للملغى فقط، ولا يحدد الطلب الصريح.',
    recommendationAr: 'السماح بعد صفحة تحذير ونقرة تأكيد، مع شريط دائم يذكر أنه ملغى.',
    options: [
      { id: 'interstitial', labelAr: 'السماح بعد تحذير وتأكيد', consequenceAr: 'يبقى العرض الافتراضي ممنوعًا، ويمكن فحص الإصدار الملغى عمدًا.' },
      { id: 'refuse', labelAr: 'المنع دائمًا', consequenceAr: 'قاعدة أشد من الأساس، تحتاج طلب تغيير مسجلًا.' },
    ],
  },
  {
    id: 'U10', titleAr: 'صلاحيات الناشر بعد نقل الملكية',
    questionAr: 'هل يحتفظ المالك السابق بصلاحية النشر بعد نقل الملكية حتى يزيله المالك الجديد؟',
    whyAr: 'الأساس صامت؛ المسودة الحالية تبقي قائمة الناشرين كما هي مع تحذير في أداة النشر.',
    recommendationAr: 'الإبقاء مع التحذير، لأنه السلوك المكتوب والمختبر في المسودات.',
    options: [
      { id: 'keep', labelAr: 'الإبقاء مع تحذير', consequenceAr: 'على المالك الجديد إزالة الناشر السابق بنفسه.' },
      { id: 'revoke', labelAr: 'الإزالة التلقائية عند النقل', consequenceAr: 'تغيير في العقد والاختبارات T1-12.' },
    ],
  },
  {
    id: 'U14', titleAr: 'معنى مهلة العشر ثوانٍ',
    questionAr: 'هل مهلة 10 ثوانٍ لكل طلب شبكي، أم لتحميل الموقع كاملًا؟',
    whyAr: 'نص الأساس «مهلة 10s» لا يحدد نطاقها، وهذا يؤثر في المواقع الكبيرة.',
    recommendationAr: 'لكل طلب، دون مهلة إجمالية للتحميل.',
    options: [
      { id: 'per-request', labelAr: 'لكل طلب', consequenceAr: 'التحميل الكبير قد يستغرق أكثر من 10 ثوانٍ دون إلغاء.' },
      { id: 'whole-load', labelAr: 'للتحميل كاملًا', consequenceAr: 'قاعدة جديدة قد تفشل مواقع كبيرة سليمة.' },
    ],
  },
  {
    id: 'CR-M1-01', titleAr: 'قراءة حالة الموقع بإثباتات',
    questionAr: 'هل تُعتمد قراءة حالة عقد الموقع بإثباتات eth_getProof مع مجمع استقبال جديد STATE_POOL (1 MiB)؟',
    whyAr: 'الطريقة غير موجودة في قائمة طرق الإضافة المغلقة الحالية؛ البديل eth_call لا يربط الحالة بجذر موثق في وضع RP.',
    recommendationAr: 'الاعتماد مع شروط المراجعة الثانية (حدود الحجم وإعادة المحاولة)، مع بقاء المواقع ممنوعة من eth_getProof.',
    options: [
      { id: 'approve', labelAr: 'أعتمد طلب التغيير', consequenceAr: 'يُعدّل خط الأساس بالأسطر المقترحة، وتبقى اختبارات MPT للتنفيذ لاحقًا.' },
      { id: 'reject', labelAr: 'أرفض وأبقي خط الأساس', consequenceAr: 'تُصاغ ضمانة اللقطة بصيغة أضعف مشروطة (P36) دون ادعاء التكافؤ.' },
      { id: 'amend', labelAr: 'أطلب تعديلًا (اكتبه في الملاحظة)', consequenceAr: 'تعود الوثيقة إلى المؤلف.' },
    ],
  },
  {
    id: 'UI-TEST', testOnly: true, titleAr: 'سؤال اختبار للواجهة فقط',
    questionAr: 'سؤال تجريبي للتحقق من مسار الإجابة والاستلام. لا يعتمد أي سياسة في M1.',
    whyAr: 'لاختبار الواجهة من البداية إلى النهاية.',
    recommendationAr: 'أي خيار؛ لا أثر له على M1.',
    options: [
      { id: 'yes', labelAr: 'نعم (اختبار)', consequenceAr: 'لا أثر.' },
      { id: 'no', labelAr: 'لا (اختبار)', consequenceAr: 'لا أثر.' },
    ],
  },
];

export const findQuestion = (id) => OWNER_QUESTIONS.find((q) => q.id === id);
