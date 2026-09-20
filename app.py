import re
import streamlit as st

# ==========================================
# [함수 1] 피싱 키워드 및 위험도 분석 (함수 분리)
# ==========================================
def analyze_phishing(text):
    high_risk_words = ["검찰", "금감원", "안전계좌", "구속영장", "명의도용", "원격제어"]
    medium_risk_words = ["대출", "모바일청첩장", "택배배송", "부조금", "수수료"]
    
    score = 0
    detected_words = []
    
    for word in high_risk_words:
        if word in text:
            score += 25
            detected_words.append(word)
            
    for word in medium_risk_words:
        if word in text:
            score += 15
            detected_words.append(word)
            
    return score, detected_words

# ==========================================
# [함수 2] URL 및 APK 악성 파일 검사
# ==========================================
def check_url_risk(text):
    url_pattern = r'https?://[^\s]+|www\.[^\s]+'
    urls = re.findall(url_pattern, text)
    
    has_apk = ".apk" in text.lower()
    
    suspicious_keywords = ["bit.ly", "tinyurl", "xyz", "top", "vip", "me"]
    has_suspicious_domain = False
    for url in urls:
        for kw in suspicious_keywords:
            if kw in url.lower():
                has_suspicious_domain = True
                
    return urls, has_apk, has_suspicious_domain


# ==========================================
# [메인 화면 UI 구성]
# ==========================================
st.set_page_config(page_title="피싱 백신 SOS", page_icon="🛡️")

# 참신한 기능: 어르신 모드 토글
elder_mode = st.toggle("👵 글씨를 크게 볼래요 (어르신 쉬운 모드)")

if elder_mode:
    st.markdown("<h1 style='font-size: 38px;'>🛡️ 피싱 예방 SOS</h1>", unsafe_allow_html=True)
    st.markdown("<p style='font-size: 20px; color: red;'><b>수상한 문자가 왔나요? 아래에 붙여넣고 버튼을 누르세요!</b></p>", unsafe_allow_html=True)
else:
    st.title("🛡️ 보이스피싱 & 악성 URL 실시간 진단기")
    st.write("의심스러운 문자/대화 내용을 입력하면 피싱 위험도와 악성 링크 여부를 분석합니다.")

st.divider()

user_input = st.text_area(
    "문자 내용 입력창", 
    placeholder="예: [WEB발신] 검찰청입니다. 명의도용 사건으로 안전계좌 이체가 필요합니다. http://bit.ly/1234.apk",
    height=150
)

if st.button("🚨 위험도 진단하기", use_container_width=True):
    
    # ------------------------------------------
    # [수행평가 만점 요건] 예외 처리 3가지
    # ------------------------------------------
    if not user_input.strip():
        st.warning("⚠️ 분석할 문자 내용을 입력해 주세요!")
        
    elif len(user_input.strip()) < 5:
        st.warning("⚠️ 내용이 너무 짧습니다. 정확한 진단을 위해 5자 이상 입력해 주세요.")
        
    elif not re.search(r'[가-힣a-zA-Z]', user_input):
        st.warning("⚠️ 한글 또는 영문 텍스트가 포함된 정상적인 문장으로 입력해 주세요.")
        
    else:
        score, detected_words = analyze_phishing(user_input)
        urls, has_apk, has_suspicious_domain = check_url_risk(user_input)
        
        if has_apk:
            score += 40
        if has_suspicious_domain:
            score += 20
            
        st.divider()
        st.subheader("📊 진단 결과 리포트")
        
        if score >= 50:
            st.error(f"🚨 **[고위험] 피싱 또는 악성 앱 설치 문자로 판단됩니다!** (위험 점수: {score}점)")
            
            if elder_mode:
                st.markdown("<h2 style='color: red;'>🔴 절대 문자 안의 링크를 누르지 마세요!</h2>", unsafe_allow_html=True)
            
            if detected_words:
                st.write(f"- **감지된 피싱 단어:** {', '.join(detected_words)}")
            if has_apk:
                st.write("- **경고:** 원격제어 악성 파일(.apk) 링크가 포함되어 있습니다.")
            if has_suspicious_domain:
                st.write("- **경고:** 출처가 불분명한 단축/의심 URL이 포함되어 있습니다.")
                
            st.warning("💡 **대응 요령:** 경찰청(112)이나 금감원(1332)으로 즉시 확인 전화를 거세요.")
            
            # 차별화 기능: 가족 공유 SOS 문구 생성
            st.subheader("👨‍👩‍👧‍👦 가족/자녀에게 도움 요청하기")
            sos_message = f"[SOS 피싱 의심 경고]\n엄마/아빠가 받은 문자가 피싱 위험도 {score}점이 나왔어. 확인해줘!\n\n▶ 받은 내용: {user_input[:30]}..."
            st.code(sos_message, language="text")
            st.caption("위 박스의 글자를 복사하여 카카오톡으로 자녀에게 보내세요.")
            
        elif score >= 20:
            st.warning(f"⚠️ **[주의] 피싱 의심 요소가 일부 발견되었습니다.** (위험 점수: {score}점)")
            if detected_words:
                st.write(f"- **감지된 의심 단어:** {', '.join(detected_words)}")
            st.info("💡 모르는 번호로부터 온 대출/기관 사칭 문자는 한번 더 확인하세요.")
            
        else:
            st.success(f"🟢 **[안전] 특별한 피싱 위험 요소가 발견되지 않았습니다.** (위험 점수: {score}점)")
