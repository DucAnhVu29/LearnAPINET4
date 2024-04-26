using iText.Kernel.Pdf;
using iText.Kernel.Utils;
using iText.Bouncycastleconnector;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web;
using static LearnAPI.Models.ByteArrayPdfSplitter;

namespace LearnAPI.Models
{
    class ByteArrayPdfSplitter : PdfSplitter
    {
        private MemoryStream currentOutputStream;

        public ByteArrayPdfSplitter(PdfDocument pdfDocument) : base(pdfDocument)
        {
        }

        protected override PdfWriter GetNextPdfWriter(PageRange documentPageRange)
        {
            currentOutputStream = new MemoryStream();
            PdfWriter writer = new PdfWriter("currentOutputStream");
            return writer;
        }

        public MemoryStream CurrentMemoryStream
        {
            get { return currentOutputStream; }
        }

        public class DocumentReadyListender : IDocumentReadyListener
        {
            public List<byte[]> splitPdfs;

            private ByteArrayPdfSplitter splitter;

            public DocumentReadyListender(ByteArrayPdfSplitter splitter, List<byte[]> results)
            {
                this.splitter = splitter;
                this.splitPdfs = results;
            }

            public void DocumentReady(PdfDocument pdfDocument, PageRange pageRange)
            {
                pdfDocument.Close();
                byte[] contents = splitter.CurrentMemoryStream.ToArray();
                splitPdfs.Add(contents);
            }
        }
    }
}