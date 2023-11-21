import os
import subprocess
import requests
import sys
from reportlab.pdfgen import canvas
import matplotlib.pyplot as plt
import numpy as np

# Constante para consumo da API
API_URL_BASE = "https://cve.circl.lu/api/cve/"

## Vetores para contagem de infos ##
# conta as criticidades
rank = []
# apenas os 'ids' dos CVE's
mylist = []
# lista com as infos dos CVE's
CVElist = []

# solicitando o endereco
endereco = input('Digite o endereço da máquina que quer verificar as vulnerabilidades: ')

print('Aguarde...')
# Comando para rodar a verificação de vulnerabilidades
process = subprocess.run(['nmap','-sV', '--script','vuln', endereco],stdout=subprocess.PIPE, universal_newlines=True)
output = process.stdout # armazenando a saida do comando anterior em uma variável


# Loop para verificação e filtragem das linhas com infos necessárias
for linha in output.splitlines():
    if linha.__contains__('CVE-'):
        for aux in linha.split(':'):
            if(aux.__contains__('CVE-') and (not aux.__contains__('https') and not aux.__contains__('(') and not aux.__contains__('/')) ):
                mylist.append(aux)

# Finaliza o script caso não tenha encontrado uma vulnerabilidade
if mylist.__len__() == 0:
    print('Não foram encontradas vulnerabilidades na máquina: ' + endereco)
    sys.exit()

# Função para remover CVE's duplicados na lista
def removeDuplicates(aux):
    aux = list(dict.fromkeys(aux))
    return aux

# Chamando a função para remover CVES duplicados
mylist = removeDuplicates(mylist)

# Classe com as propriedades necessárias de um CVE
class CVE:
    def __init__(self, id, gravidade, cwe, resumo, rank):
        self.id = id
        self.gravidade = gravidade
        self.cwe = cwe
        self.resumo = resumo
        self.rank = rank

# Função para verificar a prioridade da vulnerabilidade
def verPrioridade(cvss):
    if cvss == None:
        return 'LOW'
    if cvss < 4:
        return 'LOW'
    if cvss >= 4 and cvss < 7:
        return 'MEDIUM'
    if cvss >= 7 and cvss < 9:
        return 'HIGH'
    if cvss >= 9:
        return 'CRITIC'

# Função para criar um "resumo" vísivel na tabela
def format(resumo):
  aux = resumo.split()
  cont = 1
  wordWrap = ''
  for x in aux:
    wordWrap = wordWrap + x + ' '
    if cont % 4 == 0:
      wordWrap = wordWrap + '\n'
    cont+= 1
  return wordWrap

# Verifica CVSS nulo
def verificaCVSS(cvss):
    if cvss == None:
        return 'Incógnito'
    return cvss

# Loop para pegar as infos de todos o CVE's encontrados
for idCVE in mylist:
    response = requests.get(API_URL_BASE+idCVE).json()
    cve1 = CVE(response['id'], verificaCVSS(response['cvss']), format(response['summary']), response['cwe'], verPrioridade(response['cvss']))
    CVElist.append(cve1)
    rank.append(cve1.rank)

# Função para verificar a quantidade das prioridades encontradas
def contaRank(teste):
    low = 0
    medium = 0
    high = 0
    critic = 0
    for aux in teste:
        if aux == 'LOW':
            low += 1
        if aux == 'MEDIUM': 
            medium += 1
        if aux == 'HIGH':
            high += 1
        if aux == 'CRITIC':
            critic += 1
    priority = [low, medium, high, critic]
    return priority


########## PREPARANDO O GRÁFICO ############
# Carregando o array com os dados dos rank para vizualização rápida
y = np.array(contaRank(rank))

# Etiquetas do gráfico
mylabels = ["LOW", "MEDIUM", "HIGH", "CRITIC"]

# Cores do gráfico
mycolors = ["#ffcccc","#ff3333","#990000","#330000"]

# Produzindo o gráfico
plt.pie(y, labels = mylabels, colors=mycolors)

# Adicionando legenda
plt.legend(mylabels,
          title="Gravidade",
          loc="center left",
          bbox_to_anchor=(0.8, 0.518, 0.1, 1))

# Salvando como imagem
plt.savefig('grafic.png')

################### PDF #############################
# libs auxiliares para criação do pdf
from datetime import datetime
from reportlab.platypus import Frame
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.pagesizes import A4

# libs para auxílio na formatação dos dados a serem inseridos no pdf
from reportlab.platypus import Image
from reportlab.platypus import Table, Paragraph
from reportlab.lib import colors

# lib para definir o layout da página
from reportlab.platypus import BaseDocTemplate

# pandas
import pandas as pd

# lib que possui as caracteristicas de uma folha pré formatada
from reportlab.platypus import PageTemplate

# libs para auxílio na configuração da página
from reportlab.platypus import PageBreak
from reportlab.lib.styles import getSampleStyleSheet

# definindo algumas foramatações da folha
padding = dict(
  leftPadding=72, 
  rightPadding=72,
  topPadding=72,
  bottomPadding=18)

portrait_frame = Frame(0, 0, *A4, **padding)

# função para definir a formatação que será contida em todas as páginas
def on_page(canvas, doc, pagesize=A4):
    page_num = 'Pág. ' + str(canvas.getPageNumber())
    canvas.drawRightString(pagesize[0]/1.1, 780, page_num)
    canvas.drawImage('./FAT-BRAS.png', 0, 770, width=140, height=70)

# configurando alguns detalhes da folha pré formatada
portrait_template = PageTemplate(
  id='portrait', 
  frames=portrait_frame,
  onPage=on_page, 
  pagesize=A4)

doc = BaseDocTemplate(
  'tcc.pdf',
  pageTemplates=[
    portrait_template
  ]
)

# definindo as formatações do rodapé
rodapeStyle = ParagraphStyle('rodapeStyle',
    fontName='times',
    alignment=1,
    fontSize=15
)

# definindo as formatações do cabeçalho
cabecalhoStyle = ParagraphStyle('cabecalhoStyle',
    fontName='times',
    fontSize=22,
    alignment=1,
    spaceBefore=15,
    spaceAfter=40,
)
# estilo do parágrafo que apresenta o total de vulnerabilidades
total = ParagraphStyle('total',
    fontName='times',
    alignment=2,
    fontSize=20,
    spaceBefore=15,
    spaceAfter=15
)

# estilo pronto da lib
styles = getSampleStyleSheet()

##### Passando os CVE's para uma lista no formato do df #####
lista_pd = []

for i in CVElist:
    lista_pd.append([i.id,i.gravidade, i.resumo, i.cwe, i.rank])
    


# variável que recebe o DataFrame(tabela) com os dados das vulnerabilidades
df = pd.DataFrame(lista_pd, columns=['<b>CVE</b>', '<b>GRAVIDADE</b>', '<b>RESUMO</b>', '<b>CWE</b>', '<b>PRIORIDADE</b>'])

# função que formata a tabela
def df2table(df):
    return Table(
      [[Paragraph(col) for col in df.columns]] + df.values.tolist(), 
      style=[
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('LINEBELOW',(0,0), (-1,0), 1, colors.black),
        ('INNERGRID', (0,0), (-1,-1), 0.25, colors.black),
        ('BOX', (0,0), (-1,-1), 1, colors.black),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.lightgrey, colors.white])],
      hAlign = 'LEFT')

# definição da ordem em que as coisas são adicionadas no pdf
story = [
  Paragraph('<b>RELATÓRIO DE VULNERABILIDADES</b>', cabecalhoStyle),
  Paragraph('Máquina: ' + endereco + ' - Data da varredura: ' + str(datetime.now().strftime('%d/%m/%Y %H:%M')), styles['Heading2']),
  Paragraph('________________________________________________________________________________'),
  Paragraph('Relatório de Prioridades', cabecalhoStyle),
  Image('grafic.png', width=550, height=450),
  PageBreak(),
  Paragraph('Vulnerabilidades Encontradas', cabecalhoStyle),
  df2table(df),
  Paragraph('Total de vulnerabilidades: ' + str(CVElist.__len__()), total),
  Paragraph('________________________________________________________________________________'),
  Paragraph('www.fatec.com.br', rodapeStyle)
]

# construção do pdf
doc.build(story)

print('Concluído!\nVeja o relatório em PDF na mesma pasta que esse script.')

# Removendo a imagem do gráfico do diretório
os.remove('./grafic.png')