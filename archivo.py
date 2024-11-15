import re
import json
from datetime import datetime
import matplotlib.pyplot as plt
from collections import Counter, defaultdict
import requests
import gzip
from io import StringIO
import pandas as pd
import seaborn as sns


class LogAnalyzerNASA:
    def __init__(self):
        # URL del dataset de logs de la NASA de julio 1995
        self.dataset_url = "https://raw.githubusercontent.com/elastic/examples/master/Common%20Data%20Formats/nginx_logs/nginx_logs"
        self.regex_pattern = r'(\S+) - - \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+|-)'
        self.log_entries = []

    def fetch_logs(self):
        """Descarga los logs desde la URL."""
        print("Descargando logs...")
        response = requests.get(self.dataset_url)
        if response.status_code == 200:
            return response.text.split('\n')
        else:
            raise Exception("No se pudieron descargar los logs")

    def analyze_logs(self):
        """Parsea los logs descargados y extrae la información relevante."""
        print("Analizando logs...")
        lines = self.fetch_logs()

        for line in lines:
            if not line.strip():
                continue

            match = re.match(self.regex_pattern, line)
            if match:
                client, log_time, request_method, request_path, request_protocol, response_code, bytes_transferred = match.groups()

                # Convertir log_time
                try:
                    parsed_date = datetime.strptime(log_time, '%d/%b/%Y:%H:%M:%S %z')
                    date_formatted = parsed_date.strftime('%Y-%m-%d')
                except ValueError:
                    date_formatted = log_time

                # Manejar casos donde bytes_transferred es '-'
                if bytes_transferred == '-':
                    bytes_transferred = 0
                else:
                    bytes_transferred = int(bytes_transferred)

                log_entry = {
                    'client': client,
                    'log_time': date_formatted,
                    'request_method': request_method,
                    'request_path': request_path,
                    'request_protocol': request_protocol,
                    'response_code': int(response_code),
                    'bytes_transferred': bytes_transferred
                }
                self.log_entries.append(log_entry)

        print(f"Se procesaron {len(self.log_entries)} entradas de log")

    def save_to_json(self, output_filename):
        """Guarda los datos parseados en formato JSON."""
        with open(output_filename, 'w') as f:
            json.dump(self.log_entries, f, indent=2)
        print(f"Datos guardados en {output_filename}")

    def plot_http_methods_distribution(self):
        """Genera un gráfico de torta mejorado de métodos HTTP."""
        methods_list = [entry['request_method'] for entry in self.log_entries]
        method_distribution = Counter(methods_list)

        plt.figure(figsize=(10, 6))
        colors = sns.color_palette('husl', n_colors=len(method_distribution))
        plt.pie(method_distribution.values(), labels=method_distribution.keys(),
                autopct='%1.1f%%', colors=colors, shadow=True)
        plt.title('Distribución de Métodos HTTP en Logs NASA', pad=20)
        plt.savefig('nasa_http_methods_distribution.png', bbox_inches='tight', dpi=300)
        plt.close()

    def plot_status_codes_distribution(self):
        """Genera un gráfico de barras mejorado de códigos de estado."""
        status_list = [entry['response_code'] for entry in self.log_entries]
        status_distribution = Counter(status_list)

        plt.figure(figsize=(12, 6))
        sns.barplot(x=list(status_distribution.keys()), y=list(status_distribution.values()))
        plt.title('Distribución de Códigos de Estado HTTP en Logs NASA')
        plt.xlabel('Código de Estado')
        plt.ylabel('Cantidad de Solicitudes')
        plt.xticks(rotation=0)

        # Agregar etiquetas de valor en cada barra
        for i, v in enumerate(status_distribution.values()):
            plt.text(i, v, str(v), ha='center', va='bottom')

        plt.savefig('nasa_status_codes_distribution.png', bbox_inches='tight', dpi=300)
        plt.close()

    def plot_daily_requests_trend(self):
        """Genera un gráfico de líneas mejorado de solicitudes por día."""
        daily_requests_count = defaultdict(int)
        for entry in self.log_entries:
            daily_requests_count[entry['log_time']] += 1

        dates_sorted = sorted(daily_requests_count.keys())
        counts_sorted = [daily_requests_count[date] for date in dates_sorted]

        plt.figure(figsize=(15, 6))
        sns.lineplot(x=dates_sorted, y=counts_sorted, marker='o')
        plt.title('Solicitudes Diarias en Logs NASA')
        plt.xlabel('Fecha')
        plt.ylabel('Número de Solicitudes
        plt.xticks(rotation=45)
        plt.grid(True, alpha=0.3)

        plt.savefig('nasa_daily_requests_trend.png', bbox_inches='tight', dpi=300)
        plt.close()

    def plot_top_requested_paths(self, top_n=10):
        """Genera un gráfico de barras horizontales de las rutas más solicitadas."""
        paths_list = [entry['request_path'] for entry in self.log_entries]
        top_paths = Counter(paths_list).most_common(top_n)

        plt.figure(figsize=(12, 8))
        paths, counts = zip(*top_paths)

        # Eliminar 'palette' ya que no es necesario
        sns.barplot(x=counts, y=paths)

        plt.title(f'Top {top_n} Rutas más Solicitadas')
        plt.xlabel('Cantidad de Solicitudes')
        plt.ylabel('Ruta')

        plt.savefig('nasa_top_requested_paths.png', bbox_inches='tight', dpi=300)
        plt.show()
        plt.close()

    def generate_analysis_report(self):
        """Genera un informe detallado con estadísticas."""
        total_requests_count = len(self.log_entries)
        methods_count = Counter([entry['request_method'] for entry in self.log_entries])
        status_codes_count = Counter([entry['response_code'] for entry in self.log_entries])
        unique_clients_count = len(set([entry['client'] for entry in self.log_entries]))
        total_bytes_transferred = sum([entry['bytes_transferred'] for entry in self.log_entries])

        # Calcular los paths más comunes
        top_paths = Counter([entry['request_path'] for entry in self.log_entries]).most_common(10)

        report_data = {
            'total_requests': total_requests_count,
            'unique_clients': unique_clients_count,
            'total_bytes_transferred': total_bytes_transferred,
            'average_bytes_per_request': total_bytes_transferred / total_requests_count if total_requests_count > 0 else 0,
            'http_methods_count': dict(methods_count),
            'status_codes_count': dict(status_codes_count),
            'top_10_paths': dict(top_paths)
        }

        with open('nasa_analysis_report.json', 'w') as f:
            json.dump(report_data, f, indent=2)

        print("Reporte generado en nasa_analysis_report.json")


def main():
    try:
        # Crear instancia del analizador
        analyzer = LogAnalyzerNASA()

        # Procesar logs
        analyzer.analyze_logs()
        analyzer.save_to_json('nasa_logs_processed.json')

        # Generar visualizaciones
        print("Generando visualizaciones...")
        analyzer.plot_http_methods_distribution()
        analyzer.plot_status_codes_distribution()
        analyzer.plot_daily_requests_trend()
        analyzer.plot_top_requested_paths()

        # Generar reporte
        analyzer.generate_analysis_report()

        print("Análisis completado exitosamente!")

    except Exception as e:
        print(f"Error durante el análisis: {str(e)}")


if __name__ == "__main__":
    main()
