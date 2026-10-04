import streamlit as st
from dotenv import load_dotenv
from modsec_generator import (
    fetch_cve,
    extract_cve_info,
    generate_modsec_rule,
    parse_llm_response,
    validate_rule_syntax,
)

load_dotenv()

st.set_page_config(page_title="ModSecurity Generator")

st.title("ModSecurity Generator")
st.write("Генератор черновиков правил ModSecurity для CVE. **Требует проверки человеком.**")

cve_id = st.text_input("Введите CVE ID:", placeholder="CVE-2024-4577")

if st.button("Сгенерировать правило"):
    if not cve_id:
        st.warning("Введите CVE ID")
    else:
        # Шаг 1: получаем данные из NVD
        with st.spinner(f"Загружаю данные о {cve_id} из NVD..."):
            data = fetch_cve(cve_id)
            info = extract_cve_info(data) if data else None

        if info is None:
            st.error(f"Не удалось получить данные о {cve_id}. Проверь ID.")
        else:
            st.success(f"Данные получены: CVSS {info['cvss_score']}, {info['cwe']}")

            # Шаг 2: генерируем правило
            with st.spinner("LLM генерирует правило (может занять до 60 секунд)..."):
                try:
                    raw = generate_modsec_rule(info)
                    parsed = parse_llm_response(raw)
                except Exception as e:
                    st.error(f"Ошибка при генерации: {e}")
                    st.write("**Возможные причины:**")
                    st.write("- Rate limit у бесплатной модели (попробуй через минуту)")
                    st.write("- Модель вернула пустой ответ")
                    st.write("- Невалидный JSON в ответе")
                    st.stop()

            # Шаг 3: показываем результат
            st.subheader("Результат")

            col1, col2 = st.columns(2)
            with col1:
                st.metric("Detectable", "Да" if parsed.get("detectable") else "Нет")
            with col2:
                st.metric("False Positive Risk", parsed.get("false_positive_risk", "—"))

            if parsed.get("detectable"):
                st.subheader("Правило ModSecurity")
                st.code(parsed["rule"], language="apache")

                # Валидация
                issues = validate_rule_syntax(parsed["rule"])
                if issues:
                    st.warning("Найдены потенциальные проблемы:")
                    for issue in issues:
                        st.write(f"• {issue}")

                st.subheader("Объяснение")
                st.write(parsed.get("explanation", "—"))

                st.subheader("Риск ложных срабатываний")
                st.write(parsed.get("false_positive_reason", "—"))
            else:
                st.info("Эта уязвимость **не детектируется** на уровне WAF.")
                st.write(parsed.get("reason", "—"))