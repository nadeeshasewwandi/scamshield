import csv
import os
import random

random.seed(42)

OUTPUT_PATH = "backend/data/dataset.csv"

english_spam = [
    "URGENT: Your bank account will be locked in 24 hours. Verify your identity now at http://secure-bank-update.xyz.",
    "Congratulations! You have been selected for a free cash prize. Claim it here: http://prize-claim.club.",
    "Your package delivery failed. Confirm your address immediately at http://delivery-update.top.",
    "Final notice: Unauthorized login detected. Reset your password at http://account-secure.ga.",
    "You are eligible for a refund of $450. Click here to complete the claim: http://refund-fast.tk.",
    "Your email has been compromised. Verify access now at http://securemail-login.ml.",
    "Limited time offer: Get a new phone for free. Claim here: http://gift-offer.click.",
    "Your payment was declined. Update billing details at http://billing-verify.work.",
    "You have won a lottery prize of $1000. Confirm your details on http://lottery-claim.xyz.",
    "Security alert: Unusual activity detected. Confirm your account at http://account-verify.cf."
]

english_suspicious = [
    "Your profile needs an update. Please verify the details on our portal.",
    "We found a problem with your account. Review the account activity to keep it active.",
    "Important notice: Your subscription may be cancelled unless you check your billing information.",
    "Please verify the login attempt from a new device to avoid service interruption.",
    "Your payment was declined. Review your payment method in the app.",
    "We sent a verification code to your phone. Enter it now to continue.",
    "Possible security issue detected. Confirm your identity on the website.",
    "Your account settings appear incomplete. Please update them as soon as possible.",
    "There was a problem processing your order. Check your account to correct it.",
    "Your delivery information is missing. Please confirm the address before shipment."
]

english_safe = [
    "Hi, can we reschedule our meeting from 3pm to 4pm tomorrow?",
    "Your appointment with Dr. Silva is confirmed for Friday at 9:30 AM.",
    "The invoice for your internet bill is ready. Total due is $45 and payment is due by the 20th.",
    "Your parcel has shipped and is expected to arrive in 2-3 business days.",
    "Please review the attached project report and send feedback before the deadline.",
    "Happy birthday! Wishing you a wonderful celebration with family.",
    "The team lunch is on Wednesday at the downtown café. Please join us.",
    "Your class has been moved to room B1 for tomorrow's lecture.",
    "Family dinner is scheduled this Sunday at 7pm at my house.",
    "Thank you for your payment. Your subscription has been renewed successfully."
]

singlish_spam = [
    "oya account eka block wena hati. click karanna http://secure-login.ga kiyala.",
    "oya godak luck ekak thiyenawa. claim karanna http://prize-claim.club.",
    "bank account eka update karanna. ehtakota winas karanna ba. http://bank-update.tk.",
    "oya login widiyata secure karanna. https://account-verify.ml address ekata yanna.",
    "package eka delivery wena nathnam refund nathi wei. confirm karanna http://delivery-check.xyz.",
    "wahaama login verify karanna. nethnam account eka lock wenawa. http://verify-acc.cf.",
    "oya salary refund eka claim karanna http://pay-claim.top.",
    "ATM card eka block una. PIN eka enter karanna http://atm-secure.click.",
    "prize eka yawanna link eka click karanna. http://gift-win.club.",
    "oya password eka update karanna thaniyama. http://password-update.work.",
]

singlish_suspicious = [
    "mama kiyanna one, oya account eka verify karanna. nethnam close wenawa.",
    "oya password eka update karanna one. account eka block wenawa kiyala.",
    "bank account eka restore karanna one. ehema ne nathnam ban wenawa.",
    "account eka athulata log wenna. password eka hariyata update karanna.",
    "online account ekata verify karanna. nethnam login problems hoyaganna puluwan.",
    "oyage number ekata code ekak yawala thiyenawa. enter karanna now.",
    "oya registration details update karanna. epa nam service eka stop wenawa.",
    "payment method eka check karanna. ehema nathnam subscription eka kotanava.",
    "oya address eka confirm karanna. delivery eka avoid wenna puluwan nam.",
    "thawath currencies account eka update karanna. nethnam access eka lose wenawa." 
]

singlish_safe = [
    "mama office ekata yanawa. hithanna puluwan nam call karanna.",
    "oya heta meeting ekata enawada? location eka City Tower.",
    "api weekend ekata catch up karamu. obe house ekata enna puluwanda?",
    "oya assignment eka submit karanna one. deadline eka monawa hari now.",
    "hari obata thank you. lunch ekata yamu api salakanna.",
    "oya lamayi school eke programme ekata aya adalawa.",
    "movie ticket tika gananna eyata danaganna.",
    "oya cousin ge birthday party ekata ahala inna.",
    "weather eka hondai. apita weekend ekata picnic yamu.",
    "oya train ticket ekata update ekak thiyenawa. seat eka confirm karanna."
]

sinhala_spam = [
    "ඔබගේ බැංකු ගිණුම අවලංගු කිරීමට සටහන් කර ඇත. http://secure-account.tk වෙත වහාම පිවිසෙන්න.",
    "ඔබට රු 50,000 ක ත්‍යාගයක් දින ඇති අතර මෙතැනින් රැගෙන යන්න http://prize-claim.club.",
    "ඔබගේ ගිණුමේ අක්‍රීය වීමට තත්පර 30ක් පමණ ඉතිරිවී ඇත. තහවුරු කරන්න http://account-verify.ga.",
    "ඔබගේ තොරතුරු යාවත්කාලීන කිරීමට මෙම link එක click කරන්න http://bank-secure.cf.",
    "ඔබගේ ණය එකතුව නරක බවයි. වහාම බලන්න http://loan-update.ml.",
    "ඔබගේ ගිණුම ක්ෂණිකව අත්හිටුවනු ඇත. බලන්න http://verify-account.xyz.",
    "අක්ලිප් වූ package එක නවීන කරන්න. මෙතැනින් click කර ඊට credit ලබා ගන්න http://delivery-check.work.",
    "ඔබට ලැබුණු Sri Lanka Lottery දින ලද බවයි. ගෙවීම සහතික කරන්න http://lottery-win.click.",
    "ඔබගේ ලොගින් ඕනෑම අවස්ථාවක අවසරකින් තොරව සිදු වීමක් වාර්තා විය. තහවුරු කරන්න http://secure-login.top.",
    "පෙරහුරු අංකය verify කර නොමැතිව password එක update කරන්න. http://password-update.tk.",
]

sinhala_suspicious = [
    "ඔබගේ ගිණුම verify කර නොමැතිනම් සේවාව නවත්වනු ඇත.",
    "අලුත් දැන්වීමක්: ඔබට account එක නැවත සක්‍රීය කිරීමට අවශ්‍යයි.",
    "ඔබගේ payment තොරතුරු සමහර විට සම්පූර්ණ නැත. කරුණාකර හොයා බලන්න.",
    "අසත්‍ය ලොග්-ඉන් උත්සාහයක් හමු විය. ඔබගේ වටිනා තොරතුරු තහවුරු කරන්න.",
    "ඔබගේ පාස්වර්ඩ් යාවත්කාලීන කිරීම කලයුතුය. නැතහොත් login පහසුකම අහිමි වේ.",
    "කට්ටිනෙ හදුනාගත් විට ඔබේ ගිණුම lock විය හැකිය.",
    "ඔබගේ අංකය කිසිදු සත්‍යාපන තහවුරු කර නොමැතිව login විය. පරීක්ෂා කරන්න.",
    "delivery තොරතුරැ නිවැරදි කර නොමැති නම් package එක return වේ.",
    "ඔබගේ profile එක update කර නොමැති නම් account සබල කර නොගනු ලැබේ.",
    "ඔබගේ email එකට security alert එකක් එතැන් සිටියායි. තහවුරු කරන්න."
]

sinhala_safe = [
    "ඔබගේ හෙට මහර යන්නට යන සජීවී තොරතුරු පහත දැක්වේ.",
    "අද සවස 6 ට class එක පැවැත්වේ. කරුණාකර කාලයට පැමිණෙන්න.",
    "ඔබගේ invoice එක සාර්ථකව ගෙවා ඇත. ස්තුතියි.",
    "අපි ඉදිරි සතියේ project update එක ගැන සාකච්ඡා කරමු.",
    "ඔබේ දරුවාගේ පාසල් සම්මේලනය සිකුරාදා වේ.",
    "ඔබට appointment එක පොරොන්දු කර ඇත. පැමිණෙන්න 10.30 ට.",
    "ඔබගේ package එක නැවත සකස් කර ඇත. ලගදීම පැමිණේ.",
    "අද පසු පස 5 ට meeting එක conference room 3 දීයි.",
    "ඔබගේ දූපත් ගෙවීම සාර්ථකයි. ලිපිය ඉදිරියට ගිණුමේ යාවත්කාලීන කර ඇත.",
    "අපිට ඔබේ දුරකථන අංකය අවශ්‍යයි, කරුණාකර හෝ දැනුම් දෙන්න.",
]

languages = [
    ("english", english_spam, english_suspicious, english_safe),
    ("singlish", singlish_spam, singlish_suspicious, singlish_safe),
    ("sinhala", sinhala_spam, sinhala_suspicious, sinhala_safe),
]

rows = []

for lang, spam_templates, suspicious_templates, safe_templates in languages:
    for i in range(1200):
        template = random.choice(spam_templates)
        rows.append((1, template.replace("http://", "http://")))
    for i in range(400):
        template = random.choice(suspicious_templates)
        rows.append((1, template))
    for i in range(400):
        template = random.choice(safe_templates)
        rows.append((0, template))

random.shuffle(rows)

os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["label", "text"])
    writer.writerows(rows)

print(f"Generated {len(rows)} rows in {OUTPUT_PATH}")
